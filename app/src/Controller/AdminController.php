<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

final class AdminController extends AbstractController
{
    #[Route('/api/admin/ping', name: 'api_admin_ping', methods: ['GET'])]
    #[IsGranted('ROLE_ADMIN')]
    public function ping(): JsonResponse
    {
        return $this->json([
            'ok' => true,
            'message' => 'Hello admin',
        ]);
    }
}
