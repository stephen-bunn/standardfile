# Copyright (c) 2018 Stephen Bunn <stephen@bunn.io>
# MIT License <https://opensource.org/licenses/MIT>

import os
import hashlib
import binascii
import textwrap
from pathlib import Path
from typing import Any, List, Generic, TypeVar

import attr
from requests import Session
from requests_toolbelt.sessions import BaseUrlSession
from Crypto.Cipher import AES

import ujson

from . import constants, exceptions
from .auth import AuthKeys
from .item import Item
from .cryptography import Cryptographer
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
    sync_parent = attr.ib(type=str, default=os.getcwd(), converter=Path)
    uuid = attr.ib(type=str, default=None, init=False)
    auth_keys = attr.ib(type=AuthKeys, default=None, init=False, repr=False)
    items = attr.ib(type=dict, default=attr.Factory(dict), init=False, repr=False)

    __authenticated = False
    __sync_token = None
    __cursor_token = None

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

    @property
    def sync_dir(self) -> Path:
        """Returns the sync directory for the user.

        :return: The local sync directory
        :rtype: Path
        """

        if not self.uuid:
            raise exceptions.AuthRequired(
                f"{self.email!r} must be authenticated before sync directory can exist"
            )
        return self.sync_parent.joinpath(self.uuid)

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
        digest = binascii.b2a_hex(
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

        self.auth_keys = self._build_keys(password, self._pw_salt, self._pw_cost)
        params["password"] = self.auth_keys.password_key
        result = self._make_request("post", "sign_in", params=params)

        self.uuid = result["user"]["uuid"]
        self.session.headers.update({"Authorization": f"Bearer {result['token']}"})
        self.__authenticated = True

    def sync(self, items: List[Item] = [], full: bool = False) -> dict:
        """Syncs the authenicated user's items.

        :param items: A list of items to sync to the remote, defaults to []
        :type items: List[Item], optional
        :param full: Indicates if sync should be full sync, defaults to False
        :type full: bool, optional
        :raises exceptions.AuthRequired: If the calling user is not authenticated
        :return: The server response dictionary
        :rtype: dict
        """
        if not self.authenticated:
            raise exceptions.AuthRequired(
                f"{self.email!r} must login before they can sync"
            )

        if not self.sync_dir.is_dir():
            self.sync_dir.mkdir()

        params = {}
        if self.__sync_token and not full:
            params["sync_token"] = self.__sync_token
        if isinstance(items, list) and len(items) > 0:
            params["items"] = ujson.dumps([item.to_dict() for item in items])
        result = self._make_request("post", "sync", params=params)

        # handle new items
        for item in result.get("retrieved_items", []):
            item = Item.from_dict(item)
            self.items[item.uuid] = item

            with self.sync_dir.joinpath(item.uuid).open("w") as stream:
                ujson.dump(item.to_dict(), stream)

        # handle updated items
        for item in result.get("saved_items", []):
            item = Item.from_dict(item)
            if item.uuid not in self.items:
                self.items[item.uuid] = item

            write_to = self.sync_dir.joinpath(item.uuid)
            if write_to.is_file():
                with write_to.open("r") as stream:
                    local_content = ujson.load(stream)
                    remote_content = item.to_dict()

                    del remote_content["content"]
                    local_content.update(remote_content)

                    with write_to.open("w") as rewrite_stream:
                        ujson.dump(local_content, rewrite_stream)

        # TODO: handle unsaved items

        self.__sync_token = result.get("sync_token")
        self.__cursor_token = result.get("cursor_token")

        return result

    def decrypt(self, item: Item) -> dict:
        """Decrypt a user's item.

        :param item: The item to decrypt
        :type item: Item
        :raises ValueError: If the item has no content
        :raises exceptions.AuthRequired: If the calling user isn't authenticated yet
        :raises exceptions.TamperDetected: When the local uuid doesn't match the item id
        :return: The resulting content dictionary
        :rtype: dict
        """

        if not self.authenticated:
            raise exceptions.AuthRequired(
                f"{self.email!r} must login before they can decrypt"
            )
        if not item.content or len(item.content) <= 0:
            raise ValueError(f"item {item!r} has no content")

        enc_string = Cryptographer.parse_string(item.enc_item_key)
        if item.uuid != enc_string.uuid:
            raise exceptions.TamperDetected(
                (
                    f"item uuid {item.uuid!r} does not match encryption key "
                    f"uuid {enc_string.uuid!r}"
                )
            )

        item_key = Cryptographer.decrypt_string(
            enc_string,
            binascii.a2b_hex(self.auth_keys.master_key),
            binascii.a2b_hex(self.auth_keys.auth_key),
        )

        item_split = len(item_key) // 2
        (item_encryption_key, item_auth_key) = (
            item_key[:item_split],
            item_key[item_split:],
        )

        content_string = Cryptographer.parse_string(item.content)
        if item.uuid != content_string.uuid:
            raise exceptions.TamperDetected(
                (
                    f"item uuid {item.uuid!r} does not match content "
                    f"uuid {content_string.uuid!r}"
                )
            )

        return ujson.loads(
            Cryptographer.decrypt_string(
                content_string,
                binascii.a2b_hex(item_encryption_key),
                binascii.a2b_hex(item_auth_key),
            )
        )
