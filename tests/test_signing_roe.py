import pytest

from aegis.engagement import load_roe, sign_manifest, verify_manifest
from aegis.engagement.signing import (
    SignatureBundle,
    SigningError,
    generate_keypair,
)

ROE_PATH = "configs/roe.example.yaml"


def _signed_roe():
    roe = load_roe(ROE_PATH)
    client_priv, client_pub = generate_keypair()
    tester_priv, tester_pub = generate_keypair()
    sigs = SignatureBundle(
        client=sign_manifest(roe, client_priv),
        tester=sign_manifest(roe, tester_priv),
    )
    keys = {"client": client_pub, "tester": tester_pub}
    return roe, sigs, keys


def test_valid_signatures_verify():
    roe, sigs, keys = _signed_roe()
    assert verify_manifest(roe, sigs, keys) is True


def test_tampered_manifest_fails_closed():
    roe, sigs, keys = _signed_roe()
    # Mutate the manifest after signing.
    roe.engagement.client = "Evil Corp"
    with pytest.raises(SigningError):
        verify_manifest(roe, sigs, keys)


def test_missing_signature_fails_closed():
    roe, sigs, keys = _signed_roe()
    with pytest.raises(SigningError):
        verify_manifest(roe, {"client": sigs.client, "tester": ""}, keys)


def test_wrong_key_fails_closed():
    roe, sigs, _ = _signed_roe()
    _, other_pub = generate_keypair()
    with pytest.raises(SigningError):
        verify_manifest(roe, sigs, {"client": other_pub, "tester": other_pub})


def test_manifest_hash_is_deterministic():
    roe = load_roe(ROE_PATH)
    assert roe.manifest_hash() == load_roe(ROE_PATH).manifest_hash()
