FROM php:8.4-cli

RUN apt-get update && apt-get install -y \
    git unzip zip \
    libzip-dev libicu-dev libxml2-dev \
  && docker-php-ext-install \
    intl pdo_mysql zip xml \
  && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /app
