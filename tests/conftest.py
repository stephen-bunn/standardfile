# Copyright (c) 2018 Stephen Bunn <stephen@bunn.io>
# MIT License <https://opensource.org/licenses/MIT>

import pytest


TESTING_USERS = [("user@example.com", "testing",)]


@pytest.fixture(scope="session", params=TESTING_USERS)
def testing_user(request):
    return request.param
