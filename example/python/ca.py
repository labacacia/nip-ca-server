# Copyright 2026 INNO LOTUS PTY LTD
# SPDX-License-Identifier: Apache-2.0
"""CA key management and certificate issuance for NIP CA Server."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

PBKDF2_ITERS = 600_000
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32

# NPS-RFC-0002 §4 — provisional OIDs (replace post-IANA PEN assignment).
_OID_EKU_AGENT          = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1.1")
_OID_EKU_NODE           = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1.2")
_OID_NID_ASSURANCE_LVL  = x509.ObjectIdentifier("1.3.6.1.4.1.99999.2.1")


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_LEN,
                     salt=salt, iterations=PBKDF2_ITERS)
    return kdf.derive(passphrase.encode())


def _raw_private_bytes(priv: Ed25519PrivateKey) -> bytes:
    """Return the 32-byte seed."""
    return priv.private_bytes(serialization.Encoding.Raw,
                               serialization.PrivateFormat.Raw,
                               serialization.NoEncryption())


def _raw_public_bytes(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def pub_key_string(pub: Ed25519PublicKey) -> str:
    return "ed25519:" + _raw_public_bytes(pub).hex()


def save_key(priv: Ed25519PrivateKey, path: str, passphrase: str) -> None:
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    dk = _derive_key(passphrase, salt)
    plaintext = _raw_private_bytes(priv)
    ciphertext = AESGCM(dk).encrypt(nonce, plaintext, None)
    envelope = {
        "version": 1,
        "algorithm": "ed25519",
        "pub_key": pub_key_string(priv.public_key()),
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
    }
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(envelope, f)
    os.chmod(path, 0o600)


def load_key(path: str, passphrase: str) -> Ed25519PrivateKey:
    with open(path) as f:
        env = json.load(f)
    salt = bytes.fromhex(env["salt"])
    nonce = bytes.fromhex(env["nonce"])
    ct = bytes.fromhex(env["ciphertext"])
    dk = _derive_key(passphrase, salt)
    try:
        seed = AESGCM(dk).decrypt(nonce, ct, None)
    except Exception as exc:
        raise ValueError("Key decryption failed — wrong passphrase?") from exc
    return Ed25519PrivateKey.from_private_bytes(seed)


def _canonical_json(d: dict) -> bytes:
    return json.dumps(
        {k: d[k] for k in sorted(d)},
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()


def sign_dict(priv: Ed25519PrivateKey, d: dict) -> str:
    """Sign a dict (canonical JSON, sorted keys) and return 'ed25519:<b64>'."""
    sig = priv.sign(_canonical_json(d))
    return "ed25519:" + base64.b64encode(sig).decode()


def issue_cert(
    priv: Ed25519PrivateKey,
    ca_nid: str,
    subject_nid: str,
    subject_pub_key: str,
    entity_type: str,
    capabilities: list[str],
    scope: dict,
    validity_days: int,
    serial: str,
    metadata: dict | None = None,
) -> dict:
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=validity_days)
    unsigned = {
        "capabilities": capabilities,
        "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "issued_by": ca_nid,
        "nid": subject_nid,
        "pub_key": subject_pub_key,
        "scope": scope,
        "serial": serial,
    }
    signature = sign_dict(priv, unsigned)
    cert = {**unsigned, "signature": signature}
    if metadata:
        cert["metadata"] = metadata
    return cert


def generate_nid(domain: str, entity_type: str) -> str:
    uid = secrets.token_hex(8)
    return f"urn:nps:{entity_type}:{domain}:{uid}"


# ── NPS-RFC-0002 X.509 issuance ──────────────────────────────────────────────

def _ed25519_pub_from_string(pub_key_string: str) -> Ed25519PublicKey:
    """Parse 'ed25519:<hex>' (CA Server convention) into an Ed25519 public key."""
    if not pub_key_string.startswith("ed25519:"):
        raise ValueError(f"Unsupported public key format: {pub_key_string!r}")
    raw = bytes.fromhex(pub_key_string[len("ed25519:"):])
    return Ed25519PublicKey.from_public_bytes(raw)


def _name(nid: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nid)])


def load_or_create_root_cert(
    priv: Ed25519PrivateKey, ca_nid: str, root_path: str,
) -> x509.Certificate:
    """Load self-signed X.509 root from disk, or generate a fresh 5-year root."""
    if os.path.exists(root_path):
        with open(root_path, "rb") as f:
            return x509.load_der_x509_certificate(f.read())

    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(ca_nid))
        .issuer_name(_name(ca_nid))
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365 * 5))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
    )
    root = builder.sign(private_key=priv, algorithm=None)
    os.makedirs(os.path.dirname(root_path) or ".", exist_ok=True)
    with open(root_path, "wb") as f:
        f.write(root.public_bytes(serialization.Encoding.DER))
    return root


def _issue_x509_leaf(
    subject_nid: str,
    subject_pub: Ed25519PublicKey,
    ca_priv:     Ed25519PrivateKey,
    ca_nid:      str,
    entity_type: str,
    not_before:  datetime,
    not_after:   datetime,
    serial_int:  int,
) -> x509.Certificate:
    eku_oid = _OID_EKU_NODE if entity_type == "node" else _OID_EKU_AGENT
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject_nid))
        .issuer_name(_name(ca_nid))
        .public_key(subject_pub)
        .serial_number(serial_int)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([eku_oid]), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(subject_nid)]),
            critical=False,
        )
        # Custom extension: id-nid-assurance-level — ASN.1 ENUMERATED, default 0 (anonymous).
        .add_extension(
            x509.UnrecognizedExtension(_OID_NID_ASSURANCE_LVL, bytes([0x0A, 0x01, 0x00])),
            critical=False,
        )
    )
    return builder.sign(private_key=ca_priv, algorithm=None)


def issue_cert_x509(
    priv:            Ed25519PrivateKey,
    ca_nid:          str,
    root_cert:       x509.Certificate,
    subject_nid:     str,
    subject_pub_key: str,                # "ed25519:<hex>" per CA Server convention
    entity_type:     str,
    capabilities:    list[str],
    scope:           dict,
    validity_days:   int,
    serial:          str,                # CA Server's "0xABCD..." hex string
    metadata:        dict | None = None,
) -> dict:
    """
    Issue a v2 IdentFrame with both v1 Ed25519 signature AND a 2-cert X.509 chain
    (leaf + self-signed root). Non-breaking: v1 verifiers ignore cert_format/cert_chain.
    """
    cert = issue_cert(priv, ca_nid, subject_nid, subject_pub_key, entity_type,
                       capabilities, scope, validity_days, serial, metadata)

    subject_pub = _ed25519_pub_from_string(subject_pub_key)
    not_before  = datetime.fromisoformat(cert["issued_at"].replace("Z", "+00:00"))
    not_after   = datetime.fromisoformat(cert["expires_at"].replace("Z", "+00:00"))
    serial_int  = int(serial, 16) if serial.lower().startswith("0x") else int(serial)

    leaf = _issue_x509_leaf(
        subject_nid, subject_pub, priv, ca_nid, entity_type,
        not_before, not_after, serial_int,
    )
    chain = [
        base64.urlsafe_b64encode(leaf.public_bytes(serialization.Encoding.DER)).rstrip(b"=").decode("ascii"),
        base64.urlsafe_b64encode(root_cert.public_bytes(serialization.Encoding.DER)).rstrip(b"=").decode("ascii"),
    ]
    return {**cert, "cert_format": "v2-x509", "cert_chain": chain}
