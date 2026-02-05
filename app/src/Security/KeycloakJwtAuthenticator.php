<?php

namespace App\Security;

use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Core\AlgorithmManager;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Psr\Cache\CacheItemPoolInterface;


final class KeycloakJwtAuthenticator extends AbstractAuthenticator
{
    public function __construct(
        private HttpClientInterface $httpClient,
        private CacheItemPoolInterface $cache,
        private string $jwksUri,
        private string $issuer,
        private ?string $azp = null,
    ) {}

    public function supports(Request $request): ?bool
    {
        return str_starts_with((string) $request->headers->get('Authorization'), 'Bearer ');
    }

    public function authenticate(Request $request): SelfValidatingPassport
    {
        $jwt = trim(substr((string) $request->headers->get('Authorization'), 7));

        try {
            $claims = $this->verifyJwt($jwt);
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
                
                $clientId = $claims['azp'] ?? null;
                
                if ($clientId && isset($claims['resource_access'][$clientId]['roles']) && is_array($claims['resource_access'][$clientId]['roles'])) {
                    foreach ($claims['resource_access'][$clientId]['roles'] as $r) {
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

    private function verifyJwt(string $jwt): array
    {
        $jwks = $this->getJwks();

        $serializer = new CompactSerializer();
        $jws = $serializer->unserialize($jwt);

        $algorithmManager = new AlgorithmManager([new RS256()]);
        $verifier = new JWSVerifier($algorithmManager);
        if (!$verifier->verifyWithKeySet($jws, $jwks, 0)) {
            throw new \RuntimeException('signature verification failed');
            }


        $payload = $jws->getPayload();
        if ($payload === null) {
            throw new \RuntimeException('missing payload');
        }

        $claims = json_decode($payload, true, flags: JSON_THROW_ON_ERROR);

        // minimale Claim-Checks
        if (($claims['iss'] ?? null) !== $this->issuer) {
            throw new \RuntimeException('issuer mismatch');
        }

        if (isset($claims['exp']) && time() >= (int) $claims['exp']) {
            throw new \RuntimeException('token expired');
        }

        if ($this->azp !== null && ($claims['azp'] ?? null) !== $this->azp) {
            throw new \RuntimeException('azp mismatch');
        }

        return $claims;
    }

    private function getJwks(): JWKSet
    {
        $item = $this->cache->getItem('keycloak.jwks');
        if ($item->isHit()) {
            return JWKSet::createFromKeyData($item->get());
        }

        $data = $this->httpClient->request('GET', $this->jwksUri)->toArray();
        $item->set($data);
        $item->expiresAfter(3600);
        $this->cache->save($item);

        return JWKSet::createFromKeyData($data);
    }
}
