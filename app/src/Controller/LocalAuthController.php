<?php

namespace App\Controller;

use App\Security\LocalJwtIssuer;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

final class LocalAuthController
{
    public function __construct(private LocalJwtIssuer $issuer) {}

    #[Route('/auth/local/login', methods: ['POST'])]
    public function login(Request $request): JsonResponse
    {
        $data = $request->toArray();
        $email = $data['email'] ?? null;
        $password = $data['password'] ?? null;

        if (!$email || !$password) {
            return new JsonResponse(['message' => 'Missing email/password'], 400);
        }

        $users = require \dirname(__DIR__, 2).'/config/local_users.php';

        if (!isset($users[$email]) || !password_verify($password, $users[$email]['hash'])) {
            return new JsonResponse(['message' => 'Invalid credentials'], 401);
        }

        $roles = $users[$email]['roles'] ?? ['ROLE_USER'];

        // Wir setzen die Claims so, dass dein Rollen-Mapping gleich bleibt:
        $token = $this->issuer->issue([
            'email' => $email,
            'preferred_username' => $email,
            'realm_access' => [
                'roles' => array_map(
                    fn (string $r) => strtolower(str_replace('ROLE_', '', $r)),
                    $roles
                ),
            ],
        ]);

        return new JsonResponse([
            'access_token' => $token,
            'token_type' => 'Bearer',
        ]);
    }
}
