<?php

namespace App\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

final class DebugHeadersController
{
    #[Route('/debug/headers', methods: ['GET'])]
    public function __invoke(Request $request): JsonResponse
    {
        return new JsonResponse([
            'authorization' => $request->headers->get('authorization'),
            'all' => $request->headers->all(),
        ]);
    }
}
