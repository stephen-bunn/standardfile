# Copyright (c) 2018 Stephen Bunn <stephen@bunn.io>
# MIT License <https://opensource.org/licenses/MIT>

import uuid
import string
import random

import pytest
import secrets


@pytest.fixture(scope="session")
def sample_string(request):
    return "".join(
        random.choice(string.ascii_letters + string.digits) for _ in range(16)
    )


@pytest.fixture(scope="session")
def sample_uuid(request):
    return str(uuid.uuid4())


@pytest.fixture(scope="session")
def sample_encryption_key(request):
    return secrets.token_hex(128 // 8).encode()


@pytest.fixture(scope="session")
def sample_auth_key(request):
    return secrets.token_hex(8).encode()
