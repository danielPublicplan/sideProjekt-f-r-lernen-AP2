<?php

namespace App\Security;

use Symfony\Component\Security\Core\User\UserInterface;

final class KeycloakUser implements UserInterface
{
    public function __construct(
        private string $identifier,
        private array $roles,
        private array $claims
    ) {}

    public function getUserIdentifier(): string { return $this->identifier; }

    public function getRoles(): array
    {
        // Symfony expects string roles like ROLE_*
        $roles = $this->roles ?: ['ROLE_USER'];
        return array_values(array_unique($roles));
    }

    public function eraseCredentials(): void {}
    public function claims(): array { return $this->claims; }
}
