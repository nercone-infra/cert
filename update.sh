#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

echo "> Pull"

sudo git pull

echo
echo "> Version Check"

OPENSSL_VERSIONS=$(curl -fsSL "https://api.github.com/repos/nercone-infra/openssl/releases?per_page=100" \
    | grep -o '"tag_name": *"openssl-[^"]*"' \
    | sed 's/.*openssl-\([^"]*\)".*/\1/' \
    | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' \
    | sort -V)

OPENSSL3_VERSION=$(echo "${OPENSSL_VERSIONS}" | grep -E '^3\.' | tail -1)
echo "OpenSSL ${OPENSSL3_VERSION}"

MAIN_RELEASE=$(curl -fsSL "http://deb.debian.org/debian/dists/trixie/Release")
MAIN_HASH=$(echo "${MAIN_RELEASE}" | awk '/^SHA256:/{in_sha=1; next} in_sha && / main\/binary-amd64\/Packages$/{print $1; exit}')
SECURITY_RELEASE=$(curl -fsSL "https://security.debian.org/debian-security/dists/trixie-security/Release")
SECURITY_HASH=$(echo "${SECURITY_RELEASE}" | awk '/^SHA256:/{in_sha=1; next} in_sha && / main\/binary-amd64\/Packages$/{print $1; exit}')
TRIXIE_PACKAGES_VERSION="${MAIN_HASH:0:16}-${SECURITY_HASH:0:16}"
echo "Packages (trixie) ${TRIXIE_PACKAGES_VERSION}"

for VALUE in "${OPENSSL3_VERSION}" "${MAIN_HASH}" "${SECURITY_HASH}"; do
    if [ -z "${VALUE}" ]; then
        echo "Failed to determine versions" >&2
        exit 1
    fi
done

echo
echo "> Build"

docker compose pull --ignore-buildable
docker compose build --pull \
    --build-arg OPENSSL3_VERSION="${OPENSSL3_VERSION}" \
    --build-arg TRIXIE_PACKAGES_VERSION="${TRIXIE_PACKAGES_VERSION}"

echo
echo "> Start"

docker compose up -d

echo
echo "> Reload"

./reload.sh
