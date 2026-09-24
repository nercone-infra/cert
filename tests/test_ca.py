import base64
import datetime
import importlib.util
import ipaddress
import os
import socket
import sys
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

os.environ.setdefault("RUCONET_PREFIX", "10.64.0.0/24")
os.environ.setdefault("RUCONET_DOMAIN", "ruconet.internal")

SPEC = importlib.util.spec_from_file_location("ca", Path(__file__).resolve().parent.parent / "ca" / "ca.py")
ca = importlib.util.module_from_spec(SPEC)
sys.modules["ca"] = ca
SPEC.loader.exec_module(ca)

DOMAIN = "ruconet.internal"
PREFIX = ipaddress.IPv4Network("10.64.0.0/24")


@pytest.fixture
def registry():
    return ca.Registry(PREFIX, DOMAIN)


@pytest.fixture
def authority(tmp_path, registry):
    authority = ca.Authority(tmp_path / "ca", "RucoNet CA", 7300, 30, ca.OpenSSL("openssl"))
    authority.ensure(registry)
    return authority


@pytest.fixture
def root(authority):
    return x509.load_pem_x509_certificate(authority.certificate())


def request(key) -> bytes:
    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ruconet")]))
    return builder.sign(key, hashes.SHA384()).public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def leaf(authority, registry):
    return x509.load_pem_x509_certificate(authority.sign(request(ec.generate_private_key(ec.SECP384R1())), ca.Member("gitea"), registry))


def test_root_is_version_3(root):
    assert root.version == x509.Version.v3


def test_root_is_self_issued(root):
    assert root.issuer == root.subject
    root.public_key().verify(root.signature, root.tbs_certificate_bytes, ec.ECDSA(root.signature_hash_algorithm))


def test_root_key_is_p384(root):
    assert isinstance(root.public_key(), ec.EllipticCurvePublicKey)
    assert isinstance(root.public_key().curve, ec.SECP384R1)


def test_root_signature_is_sha384(root):
    assert isinstance(root.signature_hash_algorithm, hashes.SHA384)


def test_root_basic_constraints(root):
    extension = root.extensions.get_extension_for_class(x509.BasicConstraints)
    assert extension.critical
    assert extension.value.ca
    assert extension.value.path_length == 0


def test_root_key_usage(root):
    extension = root.extensions.get_extension_for_class(x509.KeyUsage)
    assert extension.critical
    assert extension.value.key_cert_sign
    assert extension.value.crl_sign


def test_root_subject_key_identifier(root):
    extension = root.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    assert not extension.critical
    assert extension.value.digest


def test_root_name_constraints(root):
    extension = root.extensions.get_extension_for_class(x509.NameConstraints)
    assert extension.critical
    assert set(extension.value.permitted_subtrees) == {x509.DNSName(DOMAIN), x509.IPAddress(PREFIX)}
    assert not extension.value.excluded_subtrees


def test_root_validity(root):
    assert root.not_valid_after_utc - root.not_valid_before_utc == datetime.timedelta(days=7300)


def test_root_serial_number(root):
    assert 0 < root.serial_number < 2 ** 159


def test_root_is_kept(authority, registry):
    certificate = authority.certificate()
    authority.ensure(registry)
    assert authority.certificate() == certificate


def test_root_key_is_private(authority):
    assert authority.key.stat().st_mode & 0o077 == 0
    assert authority.directory.stat().st_mode & 0o077 == 0


def test_leaf_is_version_3(leaf):
    assert leaf.version == x509.Version.v3


def test_leaf_is_issued_by_root(leaf, root):
    assert leaf.issuer == root.subject
    root.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm))


def test_leaf_signature_is_sha384(leaf):
    assert isinstance(leaf.signature_hash_algorithm, hashes.SHA384)


def test_leaf_subject(leaf):
    assert leaf.subject == x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"gitea.{DOMAIN}")])


def test_leaf_subject_alternative_name(leaf):
    extension = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert not extension.critical
    assert list(extension.value) == [x509.DNSName(f"gitea.{DOMAIN}")]


def test_leaf_satisfies_name_constraints(leaf):
    for name in leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName):
        assert name == DOMAIN or name.endswith(f".{DOMAIN}")


def test_leaf_basic_constraints(leaf):
    extension = leaf.extensions.get_extension_for_class(x509.BasicConstraints)
    assert extension.critical
    assert not extension.value.ca
    assert extension.value.path_length is None


def test_leaf_key_usage(leaf):
    extension = leaf.extensions.get_extension_for_class(x509.KeyUsage)
    assert extension.critical
    assert extension.value.digital_signature
    assert not extension.value.key_cert_sign
    assert not extension.value.crl_sign
    assert not extension.value.key_encipherment


def test_leaf_extended_key_usage(leaf):
    extension = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert set(extension.value) == {ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH}


def test_leaf_key_identifiers(leaf, root):
    subject = leaf.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    authority = leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    assert not subject.critical
    assert not authority.critical
    assert subject.value == x509.SubjectKeyIdentifier.from_public_key(leaf.public_key())
    assert authority.value.key_identifier == root.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest


def test_leaf_validity(leaf):
    assert leaf.not_valid_after_utc - leaf.not_valid_before_utc == datetime.timedelta(days=30)


def test_leaf_serial_number(leaf):
    assert 0 < leaf.serial_number < 2 ** 159


def test_leaf_serial_numbers_are_unique(authority, registry):
    key = ec.generate_private_key(ec.SECP384R1())
    serials = {x509.load_pem_x509_certificate(authority.sign(request(key), ca.Member("gitea"), registry)).serial_number for _ in range(4)}
    assert len(serials) == 4


def test_leaf_uses_requested_key(authority, registry):
    key = ec.generate_private_key(ec.SECP384R1())
    certificate = x509.load_pem_x509_certificate(authority.sign(request(key), ca.Member("gitea"), registry))
    assert certificate.public_key().public_numbers() == key.public_key().public_numbers()


@pytest.mark.parametrize("key", [ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP521R1()), rsa.generate_private_key(65537, 3072)])
def test_rejects_other_keys(authority, registry, key):
    with pytest.raises(ca.AuthorityError):
        authority.sign(request(key), ca.Member("gitea"), registry)


def test_rejects_invalid_request(authority, registry):
    with pytest.raises(ca.AuthorityError):
        authority.sign(b"-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n", ca.Member("gitea"), registry)


def test_rejects_forged_request(authority, registry):
    signed = x509.load_pem_x509_csr(request(ec.generate_private_key(ec.SECP384R1()))).public_bytes(serialization.Encoding.DER)
    forged = bytearray(signed)
    forged[-1] ^= 0x01
    pem = b"-----BEGIN CERTIFICATE REQUEST-----\n" + base64.encodebytes(bytes(forged)) + b"-----END CERTIFICATE REQUEST-----\n"
    with pytest.raises(ca.AuthorityError):
        authority.sign(pem, ca.Member("gitea"), registry)


def test_expiring(authority, registry):
    certificate = authority.sign(request(ec.generate_private_key(ec.SECP384R1())), ca.Member("gitea"), registry)
    assert not authority.openssl.expiring(certificate)


def resolve(monkeypatch, result):
    def gethostbyaddr(address):
        if isinstance(result, Exception):
            raise result
        return result, [], [address]
    monkeypatch.setattr(socket, "gethostbyaddr", gethostbyaddr)


def test_find_member(monkeypatch, registry):
    resolve(monkeypatch, f"gitea.{DOMAIN}")
    assert registry.find("10.64.0.7") == ca.Member("gitea")


def test_find_member_with_trailing_dot(monkeypatch, registry):
    resolve(monkeypatch, f"gitea.{DOMAIN}.")
    assert registry.find("10.64.0.7") == ca.Member("gitea")


@pytest.mark.parametrize("address", ["", "gitea", "10.64.0", "10.64.1.7", "192.0.2.1", "::1"])
def test_find_rejects_address(monkeypatch, registry, address):
    resolve(monkeypatch, f"gitea.{DOMAIN}")
    assert registry.find(address) is None


@pytest.mark.parametrize("name", [f"gitea.example.{DOMAIN}", "gitea.example", DOMAIN, f".{DOMAIN}", f"GITEA.{DOMAIN}", f"gi_tea.{DOMAIN}"])
def test_find_rejects_name(monkeypatch, registry, name):
    resolve(monkeypatch, name)
    assert registry.find("10.64.0.7") is None


@pytest.mark.parametrize("error", [socket.herror(1, "Unknown host"), socket.gaierror(-2, "Name or service not known"), OSError("timeout")])
def test_find_rejects_unresolved(monkeypatch, registry, error):
    resolve(monkeypatch, error)
    assert registry.find("10.64.0.7") is None
