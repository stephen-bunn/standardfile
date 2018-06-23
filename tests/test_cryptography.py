# Copyright (c) 2018 Stephen Bunn <stephen@bunn.io>
# MIT License <https://opensource.org/licenses/MIT>

import random

import pytest
from hypothesis import given
from hypothesis.strategies import (
    integers,
    text,
    uuids,
    binary,
    one_of,
    sampled_from,
    data,
)
from Crypto.Cipher import AES

from standardfile.exceptions import TamperDetected
from standardfile.cryptography import Cryptographer
from standardfile.item import String


STRING_VERSIONS = (2, 3,)
valid_encrypt = (
    text(),
    uuids(),
    one_of(
        binary(min_size=16, max_size=16),
        binary(min_size=24, max_size=24),
        binary(min_size=32, max_size=32),
    ),
    binary(min_size=1),
)


@given(binary(min_size=1, max_size=32))
def test_pad(content):
    """Tests that padding content works.
    """
    padded = Cryptographer._pad(content)
    assert len(padded) % AES.block_size == 0


@given(binary(min_size=1, max_size=32))
def test_unpad(content):
    """Tests that content unpadding works with padded content.
    """
    assert Cryptographer._unpad(Cryptographer._pad(content)) == content


@given(*valid_encrypt)
def test_encrypt(unencrypted_text, item_uuid, encrypt_key, auth_key):
    """Tests that generic encrypting works.
    """
    item_uuid = str(item_uuid)
    encrypted_string = Cryptographer.encrypt(
        unencrypted_text, item_uuid, encrypt_key, auth_key
    )
    assert isinstance(encrypted_string, String)
    assert encrypted_string.uuid == item_uuid


@given(*valid_encrypt)
def test_decrypt(unencrypted_text, item_uuid, encrypt_key, auth_key):
    """Tests that generic decrypting works with generic encrypting.
    """
    decrypted_string = Cryptographer.decrypt(
        Cryptographer.encrypt(unencrypted_text, str(item_uuid), encrypt_key, auth_key),
        encrypt_key,
        auth_key,
    )
    assert isinstance(decrypted_string, str)
    assert decrypted_string == unencrypted_text


@given(
    text(),
    uuids(),
    binary(min_size=1).filter(lambda x: len(x) not in (16, 24, 32)),
    binary(min_size=1),
)
def test_encrypt_key_invalid(unencrypted_text, item_uuid, encrypt_key, auth_key):
    """Tests that ``ValueError`` is raised for unacceptable encryption keys.
    """
    with pytest.raises(ValueError):
        Cryptographer.encrypt(unencrypted_text, str(item_uuid), encrypt_key, auth_key)


@given(*(valid_encrypt + (integers().filter(lambda x: x not in STRING_VERSIONS),)))
def test_unsupported_version(
    unencrypted_text, item_uuid, encrypt_key, auth_key, version
):
    """Tests if unsupported versions are raised to the user.
    """
    with pytest.raises(ValueError):
        Cryptographer.preferred_version = f"{version:03d}"
        Cryptographer.encrypt(unencrypted_text, str(item_uuid), encrypt_key, auth_key)

    Cryptographer.preferred_version = f"{STRING_VERSIONS[0]:03d}"
    with pytest.raises(ValueError):
        encrypted_string = Cryptographer.encrypt(
            unencrypted_text, str(item_uuid), encrypt_key, auth_key
        )
        encrypted_string.version = "000"
        Cryptographer.decrypt(encrypted_string, encrypt_key, auth_key)


@given(*valid_encrypt)
def test_tamper_detection(unecrypted_text, item_uuid, encrypt_key, auth_key):
    """Tests is auth_hash tampering is correctly detected.
    """
    item_uuid = str(item_uuid)
    encrypted_string = Cryptographer.encrypt(
        unecrypted_text, item_uuid, encrypt_key, auth_key
    )
    assert isinstance(encrypted_string, String)
    real_auth_hash = encrypted_string.auth_hash
    encrypted_string.auth_hash = "".join(
        random.sample(encrypted_string.auth_hash, len(encrypted_string.auth_hash))
    )
    if encrypted_string.auth_hash != real_auth_hash:
        with pytest.raises(TamperDetected):
            Cryptographer.decrypt(encrypted_string, encrypt_key, auth_key)


@given(*valid_encrypt + (sampled_from(STRING_VERSIONS),))
def test_versions_symmetric(
    unencrypted_text, item_uuid, encrypt_key, auth_key, version
):
    """Tests if encryption versions are symmetric ``local->encrypt->decrypt = local``.
    """
    item_uuid = str(item_uuid)
    Cryptographer.preferred_version = f"{version:03d}"
    encrypted_string = Cryptographer.encrypt(
        unencrypted_text, item_uuid, encrypt_key, auth_key
    )
    assert isinstance(encrypted_string, String)
    assert encrypted_string.uuid == item_uuid
    assert encrypted_string.version == Cryptographer.preferred_version

    decrypted_string = Cryptographer.decrypt(encrypted_string, encrypt_key, auth_key)
    assert isinstance(decrypted_string, str)
    assert decrypted_string == unencrypted_text
