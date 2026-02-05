<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Core\User\UserInterface;

final class ApiMeController extends AbstractController
{
    #[Route('/api/me', methods: ['GET'])]
public function __invoke(): JsonResponse
{
    $user = $this->getUser();
    if (!$user instanceof \App\Security\KeycloakUser) {
        return $this->json(['user' => null], 200);
    }

    return $this->json([
  'id' => $user?->getUserIdentifier(),
  'roles' => $user?->getRoles(),
  'claims' => $user?->claims(),
  ]);

}

}
