# Copyright (c) 2018 Stephen Bunn <stephen@bunn.io>
# MIT License <https://opensource.org/licenses/MIT>

from standardfile.cryptography import Cryptographer
from standardfile.item import String

import pytest


def test_symmetric(sample_str, sample_uuid, sample_encryption_key, sample_auth_key):
    encrypted_string = Cryptographer.encrypt_string(
        sample_str, sample_uuid, sample_encryption_key, sample_auth_key
    )
    assert isinstance(encrypted_string, String)
    assert encrypted_string.uuid == sample_uuid
    decrypted_string = Cryptographer.decrypt_string(
        encrypted_string, sample_encryption_key, sample_auth_key
    )
    assert decrypted_string == sample_str