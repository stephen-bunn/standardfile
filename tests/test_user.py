# Copyright (c) 2018 Stephen Bunn <stephen@bunn.io>
# MIT License <https://opensource.org/licenses/MIT>

import os
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


# @given(just('get'), one_of(text(), sampled_from(list(constants.ENDPOINTS.keys()))))
# def test_make_request(method, endpoint):
#     assert callable(User._make_request)
#     (email, password) = testing_user
#     user = User.login(email, password)
#     if endpoint in constants.ENDPOINTS:
#         pass
#     else:
#         with pytest.raises(ValueError):
#             user._make_request(method, endpoint)
