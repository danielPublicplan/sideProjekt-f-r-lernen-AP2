<?php

namespace App\Security;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Contracts\HttpClient\HttpClientInterface;

final class MultiIssuerJwtAuthenticator extends AbstractAuthenticator
{
    public function __construct(
        private HttpClientInterface $httpClient,
        private CacheItemPoolInterface $cache,

        private string $keycloakIssuer,
        private string $keycloakJwksUri,
        private ?string $keycloakAzp,

        private string $localIssuer,
        private string $localPublicKeyPath,
    ) {}

    public function supports(Request $request): ?bool
    {
        return str_starts_with((string) $request->headers->get('Authorization'), 'Bearer ');
    }

    public function authenticate(Request $request): SelfValidatingPassport
    {
        $jwt = trim(substr((string) $request->headers->get('Authorization'), 7));

        try {
            $claims = $this->verifyAndGetClaims($jwt);
        } catch (\Throwable $e) {
            throw new AuthenticationException('Invalid token: '.$e->getMessage(), 0, $e);
        }

        $identifier = $claims['preferred_username'] ?? $claims['email'] ?? $claims['sub'] ?? 'unknown';

        $roles = ['ROLE_USER'];
        if (isset($claims['realm_access']['roles']) && is_array($claims['realm_access']['roles'])) {
            foreach ($claims['realm_access']['roles'] as $r) {
                $roles[] = 'ROLE_' . strtoupper((string) $r);
            }
        }
        $roles = array_values(array_unique($roles));

        return new SelfValidatingPassport(
            new UserBadge($identifier, fn () => new KeycloakUser($identifier, $roles, $claims))
        );
    }

    public function onAuthenticationSuccess(Request $request, $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return new JsonResponse(['message' => $exception->getMessage()], 401);
    }

    private function verifyAndGetClaims(string $jwt): array
    {
        // 1) Unverifiziert dekodieren, um "iss" zu lesen
        $claims = $this->decodeClaimsUnverified($jwt);
        $iss = $claims['iss'] ?? null;
        if (!$iss) {
            throw new \RuntimeException('missing iss');
        }

        // 2) Signatur prüfen - abhängig vom Issuer
        if ($iss === $this->keycloakIssuer) {
            $this->verifySignatureWithJwks($jwt, $this->getKeycloakJwks());
            // optional azp check
            if ($this->keycloakAzp !== null && ($claims['azp'] ?? null) !== $this->keycloakAzp) {
                throw new \RuntimeException('azp mismatch');
            }
        } elseif ($iss === $this->localIssuer) {
            $this->verifySignatureWithJwks($jwt, $this->getLocalJwks());
        } else {
            throw new \RuntimeException('unknown issuer');
        }

        // 3) exp prüfen
        if (isset($claims['exp']) && time() >= (int) $claims['exp']) {
            throw new \RuntimeException('token expired');
        }

        return $claims;
    }

    private function decodeClaimsUnverified(string $jwt): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new \RuntimeException('not a JWT');
        }

        $payload = $this->b64urlDecode($parts[1]);
        return json_decode($payload, true, flags: JSON_THROW_ON_ERROR);
    }

    private function verifySignatureWithJwks(string $jwt, JWKSet $jwks): void
    {
        $serializer = new CompactSerializer();
        $jws = $serializer->unserialize($jwt);

        $algorithmManager = new AlgorithmManager([new RS256()]);
        $verifier = new JWSVerifier($algorithmManager);

        if (!$verifier->verifyWithKeySet($jws, $jwks, 0)) {
            throw new \RuntimeException('signature verification failed');
        }
    }

    private function getKeycloakJwks(): JWKSet
    {
        $item = $this->cache->getItem('keycloak.jwks');
        if ($item->isHit()) {
            return JWKSet::createFromKeyData($item->get());
        }

        $data = $this->httpClient->request('GET', $this->keycloakJwksUri)->toArray();
        $item->set($data);
        $item->expiresAfter(3600);
        $this->cache->save($item);

        return JWKSet::createFromKeyData($data);
    }

    private function getLocalJwks(): \Jose\Component\Core\JWKSet
{
    $pem = file_get_contents($this->localPublicKeyPath);
    if ($pem === false) {
        throw new \RuntimeException('cannot read local public key');
    }

    $res = openssl_pkey_get_public($pem);
    if ($res === false) {
        throw new \RuntimeException('invalid local public key');
    }

    $details = openssl_pkey_get_details($res);
    if (!is_array($details) || !isset($details['rsa']['n'], $details['rsa']['e'])) {
        throw new \RuntimeException('cannot extract rsa public key details');
    }

    $n = rtrim(strtr(base64_encode($details['rsa']['n']), '+/', '-_'), '=');
    $e = rtrim(strtr(base64_encode($details['rsa']['e']), '+/', '-_'), '=');

    $jwk = new \Jose\Component\Core\JWK([
        'kty' => 'RSA',
        'use' => 'sig',
        'alg' => 'RS256',
        'kid' => 'local-rs256-1',
        'n' => $n,
        'e' => $e,
    ]);

    return new \Jose\Component\Core\JWKSet([$jwk]);
}


    private function b64urlDecode(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }
        return base64_decode(strtr($data, '-_', '+/'));
    }
}
