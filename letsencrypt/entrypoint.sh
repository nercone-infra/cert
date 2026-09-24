#!/bin/sh
set -u

DIRECTORY=/etc/letsencrypt
NAME="${LETSENCRYPT_NAME:?LETSENCRYPT_NAME is required}"
INTERVAL="${LETSENCRYPT_INTERVAL:-43200}"
RETRY="${LETSENCRYPT_RETRY:-3600}"
TOKEN="${CLOUDFLARE_API_TOKEN:?CLOUDFLARE_API_TOKEN is required}"
CREDENTIALS="${DIRECTORY}/cloudflare/credentials.ini"

credentials() {
    mkdir -p "${CREDENTIALS%/*}"
    (umask 077 && printf 'dns_cloudflare_api_token = %s\n' "${TOKEN}" > "${CREDENTIALS}.tmp")
    mv "${CREDENTIALS}.tmp" "${CREDENTIALS}"
}

issue() {
    set -f
    set --
    for DOMAIN in ${LETSENCRYPT_DOMAINS:?LETSENCRYPT_DOMAINS is required}; do
        set -- "$@" -d "${DOMAIN}"
    done
    set +f
    if [ -n "${LETSENCRYPT_EMAIL:-}" ]; then
        set -- "$@" -m "${LETSENCRYPT_EMAIL}"
    else
        set -- "$@" --register-unsafely-without-email
    fi
    certbot certonly \
        --non-interactive \
        --agree-tos \
        --dns-cloudflare \
        --dns-cloudflare-credentials "${CREDENTIALS}" \
        --dns-cloudflare-propagation-seconds 60 \
        --preferred-profile tlsserver \
        --key-type ecdsa \
        --elliptic-curve secp384r1 \
        --cert-name "${NAME}" \
        "$@"
}

renew() {
    certbot renew --non-interactive --no-random-sleep-on-renew
}

update() {
    if [ -e "${DIRECTORY}/live/${NAME}/fullchain.pem" ]; then
        renew
    else
        issue
    fi
}

trap 'exit 0' TERM INT

credentials

while true; do
    if update; then
        DELAY="${INTERVAL}"
    else
        DELAY="${RETRY}"
    fi
    sleep "${DELAY}" & wait $!
done
