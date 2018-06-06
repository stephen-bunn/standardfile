# Copyright (c) 2018 Stephen Bunn <stephen@bunn.io>
# MIT License <https://opensource.org/licenses/MIT>

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

from standardfile.cryptography import Cryptographer
from standardfile.item import String


STRING_VERSIONS = (2,)
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
    padded = Cryptographer._pad(content)
    assert len(padded) % AES.block_size == 0


@given(binary(min_size=1, max_size=32))
def test_unpad(content):
    assert Cryptographer._unpad(Cryptographer._pad(content)) == content


@given(*valid_encrypt)
def test_encrypt(unencrypted_text, item_uuid, encrypt_key, auth_key):
    item_uuid = str(item_uuid)
    encrypted_string = Cryptographer.encrypt(
        unencrypted_text, item_uuid, encrypt_key, auth_key
    )
    assert isinstance(encrypted_string, String)
    assert encrypted_string.uuid == item_uuid


@given(*valid_encrypt)
def test_decrypt(unencrypted_text, item_uuid, encrypt_key, auth_key):
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
    with pytest.raises(ValueError):
        Cryptographer.encrypt(unencrypted_text, str(item_uuid), encrypt_key, auth_key)


@given(*(valid_encrypt + (integers().filter(lambda x: x not in STRING_VERSIONS),)))
def test_unsupported_version(
    unencrypted_text, item_uuid, encrypt_key, auth_key, version
):
    with pytest.raises(ValueError):
        Cryptographer.preferred_version = f"{version:03d}"
        Cryptographer.encrypt(unencrypted_text, str(item_uuid), encrypt_key, auth_key)


@given(*valid_encrypt + (sampled_from(STRING_VERSIONS),))
def test_versions_symmetric(unencrypted_text, item_uuid, encrypt_key, auth_key, version):
    item_uuid = str(item_uuid)
    Cryptographer.preferred_version = f"{version:03d}"
    encrypted_string = Cryptographer.encrypt(unencrypted_text, item_uuid, encrypt_key, auth_key)
    assert isinstance(encrypted_string, String)
    assert encrypted_string.uuid == item_uuid
    assert encrypted_string.version == Cryptographer.preferred_version

    decrypted_string = Cryptographer.decrypt(encrypted_string, encrypt_key, auth_key)
    assert isinstance(decrypted_string, str)
    assert decrypted_string == unencrypted_text
