<?php

return [
    // email => [password_hash, roles]
    'admin@example.com' => [
        'hash' => '$2y$12$qw5KRX0Vtw9tUtWmqXN5/.ic5tGMpUWOWdzj5WVvzZ6OPYFT654RO',
        'roles' => ['ROLE_ADMIN'],
    ],
    'user@example.com' => [
        'hash' => '$2y$12$SmEqw5F/FJ293FBE2.mBreozWyxfb.gRGZCFh.M90dfZmpB5Kt33a',
        'roles' => ['ROLE_USER'],
    ],
];