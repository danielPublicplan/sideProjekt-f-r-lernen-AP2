<?php

namespace App\Security;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;

final class LocalJwtIssuer
{
    public function __construct(
        private string $issuer,
        private string $privateKeyPath,
    ) {}

    public function issue(array $claims, int $ttlSeconds = 900): string
    {
        $now = time();

        $claims = array_merge($claims, [
            'iss' => $this->issuer,
            'iat' => $now,
            'exp' => $now + $ttlSeconds,
            'typ' => 'Bearer',
            'azp' => 'local',
        ]);

        $jwk = $this->createRsaPrivateJwkFromPemFile($this->privateKeyPath);

        $algorithmManager = new AlgorithmManager([new RS256()]);
        $builder = new JWSBuilder($algorithmManager);

        $jws = $builder
            ->create()
            ->withPayload(json_encode($claims, JSON_THROW_ON_ERROR))
            ->addSignature($jwk, ['alg' => 'RS256', 'kid' => 'local-rs256-1', 'typ' => 'JWT'])
            ->build();

        return (new CompactSerializer())->serialize($jws, 0);
    }

    private function createRsaPrivateJwkFromPemFile(string $path): JWK
    {
        $pem = file_get_contents($path);
        if ($pem === false) {
            throw new \RuntimeException('cannot read local private key');
        }

        $res = openssl_pkey_get_private($pem);
        if ($res === false) {
            throw new \RuntimeException('invalid local private key');
        }

        $details = openssl_pkey_get_details($res);
        if (!is_array($details) || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA) {
            throw new \RuntimeException('not an RSA private key');
        }

        $rsa = $details['rsa'] ?? null;
        if (!is_array($rsa)) {
            throw new \RuntimeException('missing rsa details');
        }

        // helper: base64url without padding
        $b64u = static fn(string $bin) => rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');

        // Required fields for RSA private JWK: n, e, d, p, q, dp, dq, qi
        foreach (['n','e','d','p','q','dmp1','dmq1','iqmp'] as $k) {
            if (!isset($rsa[$k])) {
                throw new \RuntimeException("missing RSA component $k");
            }
        }

        return new JWK([
            'kty' => 'RSA',
            'use' => 'sig',
            'alg' => 'RS256',
            'kid' => 'local-rs256-1',

            'n'  => $b64u($rsa['n']),
            'e'  => $b64u($rsa['e']),
            'd'  => $b64u($rsa['d']),
            'p'  => $b64u($rsa['p']),
            'q'  => $b64u($rsa['q']),
            'dp' => $b64u($rsa['dmp1']),
            'dq' => $b64u($rsa['dmq1']),
            'qi' => $b64u($rsa['iqmp']),
        ]);
    }
}
