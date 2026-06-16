"""Detached-signature signing & verification, fail-closed (design §7.2).

Native Ed25519 (the same primitive minisign/age use) over the canonicalized
RoE manifest, verified against *pinned* public keys. Both the client authorizer
and the tester must sign; a missing, invalid, or modified signature aborts.

A subprocess backend for ``minisign``/``gpg`` can be layered on top of the same
``verify_manifest`` contract for orgs that mandate those tools.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from aegis.engagement.roe import RoE


class SigningError(RuntimeError):
    """Raised on any signature problem — the caller must fail closed."""


@dataclass(frozen=True)
class SignatureBundle:
    """Detached signatures for the two required parties."""

    client: str  # hex Ed25519 signature over the canonical manifest
    tester: str

    def as_dict(self) -> dict[str, str]:
        return {"client": self.client, "tester": self.tester}


# -- Key handling -----------------------------------------------------------


def generate_keypair() -> tuple[str, str]:
    """Return ``(private_hex, public_hex)`` for a fresh Ed25519 key."""
    priv = Ed25519PrivateKey.generate()
    priv_bytes = priv.private_bytes_raw()
    pub_bytes = priv.public_key().public_bytes_raw()
    return priv_bytes.hex(), pub_bytes.hex()


def _load_private(private_hex: str) -> Ed25519PrivateKey:
    try:
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex.strip()))
    except Exception as exc:
        raise SigningError(f"invalid private key: {exc}") from exc


def _load_public(public_hex: str) -> Ed25519PublicKey:
    try:
        return Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex.strip()))
    except Exception as exc:
        raise SigningError(f"invalid public key: {exc}") from exc


# -- Sign / verify ----------------------------------------------------------


def sign_bytes(data: bytes, private_hex: str) -> str:
    return _load_private(private_hex).sign(data).hex()


def sign_manifest(roe: RoE, private_hex: str) -> str:
    """Detached signature over the canonicalized manifest."""
    return sign_bytes(roe.canonical_bytes(), private_hex)


def verify_signature(data: bytes, signature_hex: str, public_hex: str) -> bool:
    pub = _load_public(public_hex)
    try:
        pub.verify(bytes.fromhex(signature_hex.strip()), data)
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_manifest(
    roe: RoE,
    signatures: SignatureBundle | dict[str, str],
    pinned_pubkeys: dict[str, str],
    *,
    required: tuple[str, ...] = ("client", "tester"),
) -> bool:
    """Verify all required signatures against pinned keys, or raise.

    Fails closed: any missing party, missing pinned key, or invalid signature
    raises ``SigningError`` (design §7.2).
    """
    sigs = signatures.as_dict() if isinstance(signatures, SignatureBundle) else dict(signatures)
    data = roe.canonical_bytes()
    for party in required:
        if party not in sigs or not sigs[party]:
            raise SigningError(f"missing signature for required party: {party!r}")
        if party not in pinned_pubkeys or not pinned_pubkeys[party]:
            raise SigningError(f"no pinned public key for party: {party!r}")
        if not verify_signature(data, sigs[party], pinned_pubkeys[party]):
            raise SigningError(
                f"signature verification FAILED for {party!r} — manifest modified or wrong key"
            )
    return True


# -- File helpers (CLI convenience) -----------------------------------------


def write_keypair(directory: str | Path, name: str) -> tuple[Path, Path]:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    priv_hex, pub_hex = generate_keypair()
    priv_path = directory / f"{name}.sec"
    pub_path = directory / f"{name}.pub"
    priv_path.write_text(priv_hex + "\n", encoding="utf-8")
    pub_path.write_text(pub_hex + "\n", encoding="utf-8")
    try:
        priv_path.chmod(0o600)
    except OSError:
        pass
    return priv_path, pub_path
