# Copyright (c) 2018 Stephen Bunn <stephen@bunn.io>
# MIT License <https://opensource.org/licenses/MIT>

import os
from pathlib import Path
from requests import Session

import pytest

from standardfile import constants, exceptions
from standardfile.user import User, UserAuth


def test_init(testing_user):
    (email, password) = testing_user
    user = User(email)
    assert isinstance(user.email, str)
    assert user.email == email
    assert isinstance(user.host, str)
    assert user.host == constants.DEFAULT_HOST
    assert isinstance(user.sync_parent, Path)
    assert user.sync_parent == Path(os.getcwd())
    assert user.uuid is None
    assert user.auth_keys is None
    assert len(user.items) == 0
    assert isinstance(user.session, Session)
    assert not user.mfa_required
    assert user.mfa_key is None
    assert user.authenticated == False


def test_login(testing_user):
    (email, password) = testing_user
    user = User(email)
    assert not user.authenticated
    assert not user.mfa_required
    assert user.mfa_key is None
    with pytest.raises(exceptions.AuthRequired):
        user.sync_dir

    user.authenticate(password)
    assert user.authenticated
    assert user.mfa_required == False
    assert user.mfa_key is None
    assert isinstance(user.sync_dir, Path)
    del user

    user = User.login(email, password)
    assert isinstance(user, User)
    assert user.authenticated
    assert user.mfa_required == False
    assert user.mfa_key is None
    assert isinstance(user.sync_dir, Path)

