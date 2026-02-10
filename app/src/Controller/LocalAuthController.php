<?php

namespace App\Controller;

use App\Entity\LocalUser;
use App\Repository\LocalUserRepository;
use App\Security\LocalJwtIssuer;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

final class LocalAuthController
{
    public function __construct(
        private LocalUserRepository $users,
        private UserPasswordHasherInterface $passwordHasher,
        private LocalJwtIssuer $issuer,
    ) {}

    #[Route('/auth/local/login', methods: ['POST'])]
    public function login(Request $request): JsonResponse
    {
        $data = $request->toArray();
        $email = $data['email'] ?? null;
        $password = $data['password'] ?? null;

        if (!$email || !$password) {
            return new JsonResponse(['message' => 'Missing email/password'], 400);
        }

        /** @var LocalUser|null $user */
        $user = $this->users->findOneBy(['email' => $email]);
        if (!$user || !$this->passwordHasher->isPasswordValid($user, $password)) {
            return new JsonResponse(['message' => 'Invalid credentials'], 401);
        }

        $roles = $user->getRoles();

        $token = $this->issuer->issue([
            'email' => $user->getEmail(),
            'preferred_username' => $user->getEmail(),
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
