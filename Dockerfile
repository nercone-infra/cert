FROM debian:trixie-slim AS openssl-builder

ARG TRIXIE_PACKAGES_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY <<'EOF' /usr/local/bin/openssl-install
#!/bin/sh
set -eu

VERSION="$1"
TARGET="$2"

case "${TARGETARCH}" in
    amd64) ARCH=x86_64 ;;
    arm64) ARCH=aarch64 ;;
    *) echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;;
esac

NAME="openssl-${VERSION}-linux-${ARCH}"
URL="https://github.com/nercone-infra/openssl/releases/download/openssl-${VERSION}"
SOURCE=$(mktemp -d)

echo "Installing OpenSSL ${VERSION} (${NAME})"

curl -fsSL -o "${SOURCE}/${NAME}.tar.gz" "${URL}/${NAME}.tar.gz"
curl -fsSL "${URL}/SHA256SUMS" | grep "  ${NAME}.tar.gz\$" | (cd "${SOURCE}" && sha256sum -c -)
mkdir -p "${SOURCE}/openssl"
tar xzf "${SOURCE}/${NAME}.tar.gz" -C "${SOURCE}/openssl" --strip-components=1

if [ -d "${SOURCE}/openssl/lib64" ]; then
    LIBRARY="${SOURCE}/openssl/lib64"
else
    LIBRARY="${SOURCE}/openssl/lib"
fi

DIRECTORY=$(LD_LIBRARY_PATH="${LIBRARY}" "${SOURCE}/openssl/bin/openssl" version -d | sed -n 's/^OPENSSLDIR: "\(.*\)"$/\1/p')

mkdir -p "${TARGET}/bin" "${TARGET}/lib" "${TARGET}/ssl" "${TARGET}/include" "${TARGET}/root${DIRECTORY%/*}"
cp -a "${SOURCE}/openssl/bin/openssl" "${TARGET}/bin/"
cp -a "${LIBRARY}"/libssl.so* "${LIBRARY}"/libcrypto.so* "${TARGET}/lib/"
cp -a "${SOURCE}/openssl/ssl/openssl.cnf" "${TARGET}/ssl/"
cp -a "${SOURCE}/openssl/include/openssl" "${TARGET}/include/"
ln -s /etc/ssl/certs "${TARGET}/ssl/certs"
ln -s /etc/ssl/certs/ca-certificates.crt "${TARGET}/ssl/cert.pem"
ln -s /usr/local/ssl "${TARGET}/root${DIRECTORY}"
chown -hR root:root "${TARGET}"
rm -rf "${SOURCE}"
EOF

RUN chmod +x /usr/local/bin/openssl-install

FROM openssl-builder AS openssl3

ARG TARGETARCH
ARG OPENSSL3_VERSION

RUN openssl-install "${OPENSSL3_VERSION}" /opt/openssl

FROM python:3-slim-trixie AS ca

COPY --from=openssl3 /opt/openssl/bin/ /usr/local/bin/
COPY --from=openssl3 /opt/openssl/lib/ /usr/local/lib/
COPY --from=openssl3 /opt/openssl/ssl/ /usr/local/ssl/
COPY --from=openssl3 /opt/openssl/root/ /

RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/00-openssl.conf && ldconfig

WORKDIR /srv

COPY ca/ca.py /srv/ca.py

EXPOSE 8080

STOPSIGNAL SIGTERM

CMD ["python3", "-u", "/srv/ca.py"]
