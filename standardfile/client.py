# Copyright (c) 2018 Stephen Bunn <stephen@bunn.io>
# MIT License <https://opensource.org/licenses/MIT>

import hashlib
import secrets

import attr
from requests_toolbelt.sessions import BaseUrlSession

from . import constants, exceptions
from .item import Item
from .user import User
from ._common import StandardFileObject


@attr.s
class StandardFileClient(StandardFileObject):
    host = attr.ib(type=str, default=constants.DEFAULT_HOST)
    port = attr.ib(type=int, default=80)
    session = attr.ib(
        type=BaseUrlSession,
        default=attr.Factory(
            lambda self: BaseUrlSession(f"{self.host}:{self.port}"), takes_self=True
        ),
        repr=False,
        init=False,
    )

    def get_user(self, email: str) -> User:
        return User(email, session=self.session)
