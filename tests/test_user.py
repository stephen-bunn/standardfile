# Copyright (c) 2018 Stephen Bunn <stephen@bunn.io>
# MIT License <https://opensource.org/licenses/MIT>

import os
import tempfile
from pathlib import Path

import pytest
from requests import Session
from hypothesis import given
from hypothesis.strategies import none, just, integers, text, dictionaries, fixed_dictionaries, composite, one_of, sampled_from

from standardfile import constants, exceptions
from standardfile.user import User, UserAuth


@composite
def error_dict(draw):
    return draw(fixed_dictionaries({
        "message": text(),
        "payload": dictionaries(text(), one_of(text(), integers(), none())),
        "tag": one_of(none(), sampled_from(list(exceptions.EXCEPTION_MAPPING.keys())))
    }))


def test_init(testing_user):
    """Tests proper initialization of a user.
    """
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
    """Tests authentication methods of a user.
    """
    (email, password) = testing_user
    user = User(email)
    assert not user.authenticated
    assert user.mfa_key is None
    assert not user.mfa_required
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


def test_init_mfa(testing_user):
    """Test initialization of user mfa information works.
    """
    (email, password) = testing_user
    user = User.login(email, password)
    assert callable(user._init_mfa)
    user._init_mfa()
    assert user.mfa_key is None
    assert user.mfa_required == False


@given(one_of(none(), error_dict()))
def test_handle_error(error):
    """Test handling of error responses works.
    """
    assert callable(User._handle_error)
    if error is None:
        assert User._handle_error(error) is None
    elif isinstance(error, dict):
        error_tag = error.get("tag")
        if error_tag:
            with pytest.raises(exceptions.EXCEPTION_MAPPING[error["tag"]]):
                User._handle_error(error)
        else:
            with pytest.raises(exceptions.StandardFileException):
                User._handle_error(error)

@given(text(), text(), integers(min_value=1, max_value=60000))
def test_build_keys(password, salt, cost):
    """Test building of authentication keys works.
    """
    assert callable(User._build_keys)
    built_keys = User._build_keys(password, salt, cost)
    assert isinstance(built_keys, UserAuth)

def test_sync(testing_user):
    """Test syncing of data.
    """
    (email, password) = testing_user
    with tempfile.TemporaryDirectory() as tempdir:
        user = User.login(email, password, sync_parent=tempdir)
        assert isinstance(user.sync_parent, Path)
        assert user.sync_parent.is_dir()
        assert isinstance(user.sync_dir, Path)
        assert not user.sync_dir.is_dir()

        sync_results = user.sync()

        sync_token = sync_results.get("sync_token")
        assert user._User__sync_token == sync_token
        cursor_token = sync_results.get("cursor_token")
        assert user._User__cursor_token == cursor_token

        retrieved_items = sync_results.get("retrieved_items", [])
        assert len(retrieved_items) == len(list(user.sync_dir.iterdir()))
        assert len(retrieved_items) == len(user.items)

        if len(user.items) > 0:
            for (_, item) in user.items.items():
                if item.content_type == "test":
                    assert user.decrypt(item) == "testing"

