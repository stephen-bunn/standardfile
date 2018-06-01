# Copyright (c) 2018 Stephen Bunn <stephen@bunn.io>
# MIT License <https://opensource.org/licenses/MIT>

import hashlib
import binascii
import textwrap
from typing import Any, List, Generic, TypeVar

import attr
from requests import Session
from requests_toolbelt.sessions import BaseUrlSession

import ujson

from . import constants, exceptions
from .auth import AuthKeys
from .item import Item
from ._common import StandardFileObject

T_User = TypeVar("User")


@attr.s
class User(Generic[T_User], StandardFileObject):
    """Defines a Standard File user.

    Defined by StandardFile at `<https://standardfile.org/#user>`__.
    """

    email = attr.ib(type=str)
    session = attr.ib(
        type=Session, default=BaseUrlSession(constants.DEFAULT_HOST), repr=False
    )
    uuid = attr.ib(type=str, default=None, init=False)
    items = attr.ib(type=list, default=attr.Factory(list), init=False, repr=False)

    __authenticated = False
    __sync_token = None

    @property
    def mfa_required(self) -> bool:
        """Indicates if multifactor authentication is required for this user.

        :return: True if mfa is required, otherwise False
        :rtype: bool
        """

        if not hasattr(self, "_mfa_required"):
            self._init_mfa()
        return self._mfa_required

    @property
    def mfa_key(self) -> str:
        """The multifactor authentication url parameter key if mfa is required.

        :return: The mfa parameter key if mfa is required, otherwise None
        :rtype: str
        """

        if not hasattr(self, "_mfa_key"):
            self._init_mfa()
        return self._mfa_key

    @property
    def authenticated(self) -> bool:
        """Indicates if the user is currently authenticated.

        :return: True if the user is authenticated, otherwise False
        :rtype: bool
        """
        return self.__authenticated

    @classmethod
    def _build_keys(
        cls,
        password: str,
        salt: str,
        cost: int,
        crypt_algo: str = "pbkdf2_hmac",
        hash_algo: str = "sha512",
        key_size: int = 768 // 8,  # TODO: get this from somehwere
    ) -> AuthKeys:
        """Builds an ``AuthKeys`` instance for a password/salt/cost pairing.

        :param password: The password to use for generating the keys
        :type password: str
        :param salt: The salt to use for generating the keys
        :type salt: str
        :param cost: The iterations to use for generating the keys
        :type cost: int
        :param crypt_algo: The cryptographic algorithm, defaults to "pbkdf2_hmac"
        :param crypt_algo: str, optional
        :param hash_algo: The hashing algorithim, defaults to "sha512"
        :param hash_algo: str, optional
        :param key_size: The size of the key to generate, defaults to ``768 // 8``
        :param key_size: int, optional
        :return: An instance of ``AuthKeys``
        :rtype: AuthKeys
        """
        digest = binascii.hexlify(
            getattr(hashlib, crypt_algo)(
                hash_algo, password.encode(), salt.encode(), cost, dklen=key_size
            )
        ).decode()
        return AuthKeys(*textwrap.wrap(digest, width=int(len(digest) / 3)))

    def _init_mfa(self):
        """Initializes the mfa properties.

        .. note:: Should only be called once. Is called by either accessing
            ``mfa_required`` or ``mfa_key`` but you don't need to worry about multiple
            calls through accessing these properties.
        """

        self._mfa_required = False
        self._mfa_key = None
        resp = self.session.get(
            constants.ENDPOINTS.get("auth_params"), params={"email": self.email}
        )
        if resp.status_code != 200:
            error = ujson.loads(resp.text).get("error")
            if error and error.get("tag", "").startswith("mfa"):
                self._mfa_required = True
                self._mfa_key = error.get("payload", {}).get("mfa_key")

    def login(self, password: str, mfa: str = None) -> T_User:
        """Logs the user into the standard file server.

        :param password: The password of the user
        :type password: str
        :param mfa: The multifactor authentication code, defaults to None
        :param mfa: str, optional
        :raises exceptions.MFARequired: If mfa is required but no ``mfa`` provided
        :returns: The newly authenticated user
        :rtype: T_User
        """
        if self.mfa_required and not mfa:
            raise exceptions.MFARequired("mfa code is required but not provided")

        params = {"email": self.email}
        if mfa:
            params[self.mfa_key] = mfa
        result = self._make_request("get", "auth_params", params=params)

        self._pw_salt = result.get("pw_salt")
        self._pw_cost = result.get("pw_cost")
        self._version = result.get("version")

        minimum_cost = 3000  # TODO: get this from somewhere
        if self._pw_cost < minimum_cost:
            raise exceptions.StandardFileException(
                f"pw_cost {self._pw_cost!r} is less than the minimum {minimum_cost!r}"
            )

        self._auth_keys = self._build_keys(password, self._pw_salt, self._pw_cost)
        params["password"] = self._auth_keys.password_key
        result = self._make_request("post", "sign_in", params=params)

        self.uuid = result["user"]["uuid"]
        self.session.headers.update({"Authorization": f"Bearer {result['token']}"})
        self.__authenticated = True

        return self

    def sync(self) -> List[Item]:
        """Syncs the authenicated user's items.

        :raises exceptions.AuthRequired: If the calling user is not authenticated
        :return: A list of retrieved items
        :rtype: List[Item]
        """
        if not self.authenticated:
            raise exceptions.AuthRequired(
                f"{self.email!r} must login before they can sync"
            )

        params = {}
        if self.__sync_token:
            params["sync_token"] = self.__sync_token
        result = self._make_request("post", "sync", params=params)

        self.items = []
        for item in result.get("retrieved_items", []):
            self.items.append(Item.from_dict(item))

        return self.items
