#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

sudo git pull

docker compose exec tls /usr/local/bin/nginx-entrypoint reload
