# Copyright (c) 2018 Stephen Bunn <stephen@bunn.io>
# MIT License <https://opensource.org/licenses/MIT>

import os
import uuid
import hashlib
import secrets
import binascii
import textwrap
from pathlib import Path
from typing import Any, List, Generic, TypeVar

import attr
import arrow
from requests import Session
from requests_toolbelt.sessions import BaseUrlSession

import ujson

from . import constants, exceptions
from .item import Item, String
from .cryptography import Cryptographer

T_User = TypeVar("User")


@attr.s
class UserAuth(object):
    """Defins a Standard File user's authentication store.
    """

    password_key = attr.ib(type=str)
    master_key = attr.ib(type=str)
    auth_key = attr.ib(type=str)


@attr.s
class User(Generic[T_User]):
    """Defines a Standard File user.

    Defined by StandardFile at `<https://standardfile.org/#user>`__.
    """

    email = attr.ib(type=str)
    host = attr.ib(type=str, default=constants.DEFAULT_HOST, repr=False)
    sync_parent = attr.ib(type=str, default=os.getcwd(), converter=Path, repr=False)
    uuid = attr.ib(type=str, default=None, init=False)
    auth_keys = attr.ib(type=UserAuth, default=None, init=False, repr=False)
    items = attr.ib(type=dict, default=attr.Factory(dict), init=False, repr=False)

    _authenticated = False
    _unsynced = []
    __sync_token = None
    __cursor_token = None

    @property
    def session(self) -> Session:
        """The session to use for requests.

        :return: The session to use for requests
        :rtype: Session
        """
        if not hasattr(self, "_session"):
            self._session = BaseUrlSession(self.host)
        return self._session

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
        return self._authenticated

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
    def _handle_error(cls, error: dict):
        """Handles error responses from the Standard File api.

        :param error: The response error dictionary
        :type error: dict
        :raises exceptions.StandardFileException: On any handled error
        """
        if error:
            error_message = error.get("message", "no error message provided")
            error_payload = error.get("payload", {})
            error_tag = error.get("tag")
            if error_tag in exceptions.EXCEPTION_MAPPING:
                raise exceptions.EXCEPTION_MAPPING[error_tag](
                    error_message, error_payload
                )
            else:
                raise exceptions.StandardFileException(error_message, error_payload)

    @classmethod
    def _build_keys(
        cls,
        password: str,
        salt: str,
        cost: int,
        crypt_algo: str = "pbkdf2_hmac",
        hash_algo: str = "sha512",
        key_size: int = 768 // 8,  # TODO: get this from somehwere
    ) -> UserAuth:
        """Builds an ``UserAuth`` instance for a password/salt/cost pairing.

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
        :return: An instance of ``UserAuth``
        :rtype: UserAuth
        """
        digest = binascii.b2a_hex(
            getattr(hashlib, crypt_algo)(
                hash_algo, password.encode(), salt.encode(), cost, dklen=key_size
            )
        ).decode()
        return UserAuth(*textwrap.wrap(digest, width=int(len(digest) / 3)))

    @classmethod
    def register(
        cls,
        email: str,
        password: str,
        host: str = constants.DEFAULT_HOST,
        cost: int = 60000,
        *args,
        **kwargs,
    ) -> T_User:
        """Registers a new user in the Standard File server.

        :param email: The email to register
        :type email: str
        :param password: The password to register
        :type password: str
        :param host: The host to register to, defaults to constants.DEFAULT_HOST
        :param host: str, optional
        :param cost: The password iteration cost, defaults to 60000
        :param cost: int, optional
        :return: A new user instance
        :rtype: T_User
        """
        session = BaseUrlSession(host)
        salt = hashlib.sha1(
            f"{email}:{secrets.token_hex(128 // 8 // 2)}".encode()
        ).hexdigest()
        auth_keys = cls._build_keys(password, salt, cost)
        response = session.post(
            constants.ENDPOINTS["register"],
            params={
                "email": email,
                "password": auth_keys.password_key,
                "pw_cost": cost,
                "pw_salt": salt,
            },
        )
        result = ujson.loads(response.text)
        if response.status_code != 200:
            cls._handle_error(result.get("error"))
        user = cls(email, host, *args, **kwargs)
        user.auth_keys = auth_keys
        user.uuid = result["user"]["uuid"]
        user.session.headers.update({"Authorization": f"Bearer {result['token']}"})
        user._authenticated = True

    @classmethod
    def login(
        cls,
        email: str,
        password: str,
        host: str = constants.DEFAULT_HOST,
        mfa: str = None,
        *args,
        **kwargs,
    ) -> T_User:
        """Shortcut to quickly create a new user instance given an email and password.

        :param email: The email of the user
        :type email: str
        :param password: The password of the user
        :type password: str
        :param host: The host to login to, defaults to constants.DEFAULT_HOST
        :param host: str, optional
        :param mfa: MFA code (if multi-factor authentication enabled), defaults to None
        :param mfa: str, optional
        :return: A new user instance
        :rtype: T_User
        """
        user = cls(email, host, *args, **kwargs)
        user.authenticate(password, mfa=mfa)
        return user

    def _make_request(self, method: str, endpoint: str, **kwargs) -> dict:
        """A simple abstraction for making a request to a standard file endpoint.

        :param method: The method to use for the request
        :type method: str
        :param endpoint: The endpoint to request for
        :type endpoint: str
        :raises ValueError: If the given endpoint does not exist
        :return: The parsed response dictionary
        :rtype: dict
        """
        endpoint = constants.ENDPOINTS.get(endpoint)
        if not endpoint:
            raise ValueError(f"no such endpoint {endpoint!r} exists")
        response = getattr(self.session, method)(endpoint, **kwargs)
        result = ujson.loads(response.text)
        if response.status_code != 200:
            self._handle_error(result.get("error"))
        return result

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

    def _build_item_path(self, item: Item) -> Path:
        """Builds the local path object for a given item.

        :param item: The item to build the local path for
        :type item: Item
        :return: The resulting path instance
        :rtype: Path
        """
        return self.sync_dir.joinpath(item.uuid)

    def _item_synced(self, item: Item) -> bool:
        """Checks if the given item is currently synced.

        :param item: The item to check
        :type item: Item
        :return: True if synced, otherwise False
        :rtype: bool
        """
        return item.uuid in self.items and item.uuid not in self._unsynced

    def _item_exists(self, item: Item) -> bool:
        """Checks if the given item exists locally.

        :param item: The item to check
        :type item: Item
        :return: True if exists locally, otherwise False
        :rtype: bool
        """
        return self._build_item_path(item).is_file()

    def authenticate(self, password: str, mfa: str = None) -> T_User:
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
        self._authenticated = True

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

        unsynced_items = []
        if isinstance(items, list) and len(items) > 0:
            unsynced_items.extend(items)
        if isinstance(self._unsynced, list) and len(self._unsynced) > 0:
            unsynced_items.extend(self._unsynced)
            self._unsynced = []
        if len(unsynced_items) > 0:
            params["items"] = ujson.dumps([item.to_dict() for item in unsynced_items])
        result = self._make_request("post", "sync", params=params)

        # handle new items
        for item in result.get("retrieved_items", []):
            item = Item.from_dict(item)
            self.items[item.uuid] = item

            with self._build_item_path(item).open("w") as stream:
                ujson.dump(item.to_dict(), stream)

        # handle updated items
        for item in result.get("saved_items", []):
            item = Item.from_dict(item)
            if item.uuid not in self.items:
                self.items[item.uuid] = item

            write_to = self._build_item_path(item)
            if write_to.is_file():
                with write_to.open("r") as stream:
                    local_content = ujson.load(stream)
                    remote_content = item.to_dict()

                    del remote_content["content"]
                    del remote_content["enc_item_key"]
                    local_content.update(remote_content)

                    with write_to.open("w") as rewrite_stream:
                        ujson.dump(local_content, rewrite_stream)

        # TODO: handle unsaved items

        self.__sync_token = result.get("sync_token")
        self.__cursor_token = result.get("cursor_token")

        return result

    def encrypt(self, content: str, content_type: str) -> Item:
        """Encrypts some content into a new item instance.

        :param content: The content to encrypt
        :type content: str
        :param content_type: Some kind of content type descriptor
        :type content_type: str
        :return: A new item instance
        :rtype: Item
        """
        item_uuid = str(uuid.uuid4())
        item_key = secrets.token_hex(512 // 8 // 2)
        key_split = len(item_key) // 2
        (encryption_key, auth_key) = (item_key[:key_split], item_key[key_split:])
        return Item(
            uuid=item_uuid,
            content=Cryptographer.encrypt(
                content,
                item_uuid,
                binascii.a2b_hex(encryption_key),
                binascii.a2b_hex(auth_key),
            ).to_string(),
            content_type=content_type,
            enc_item_key=Cryptographer.encrypt(
                item_key,
                item_uuid,
                binascii.a2b_hex(self.auth_keys.master_key),
                binascii.a2b_hex(self.auth_keys.auth_key),
            ).to_string(),
            deleted=False,
            created_at=arrow.utcnow().isoformat(),
            updated_at=arrow.utcnow().isoformat(),
            auth_hash=None,
        )

    def decrypt(self, item: Item) -> dict:
        """Decrypt a user's item.

        :param item: The item to decrypt
        :type item: Item
        :raises ValueError: If the item has no decryptable content
        :raises exceptions.AuthRequired: If the calling user isn't authenticated yet
        :raises exceptions.TamperDetected: When the local uuid doesn't match the item id
        :return: The resulting content dictionary
        :rtype: dict
        """

        if not self.authenticated:
            raise exceptions.AuthRequired(
                f"{self.email!r} must login before they can decrypt"
            )
        if item.deleted:
            raise ValueError(f"item {item!r} is deleted and cannot be decrypted")
        if not all(isinstance(_, String) for _ in (item.enc_item_key, item.content)):
            raise ValueError(f"item {item!r} has no encrypted content")

        if item.uuid != item.enc_item_key.uuid or item.uuid != item.content.uuid:
            raise exceptions.TamperDetected(
                (
                    f"item uuid {item.uuid!r} does not match both encryption uuids, "
                    f"(enc_item_key, {item.enc_item_key.uuid!r}), "
                    f"(content, {item.content.uuid!r})"
                )
            )

        item_key = Cryptographer.decrypt(
            item.enc_item_key,
            binascii.a2b_hex(self.auth_keys.master_key),
            binascii.a2b_hex(self.auth_keys.auth_key),
        )
        item_split = len(item_key) // 2
        (item_encryption_key, item_auth_key) = (
            item_key[:item_split],
            item_key[item_split:],
        )
        return Cryptographer.decrypt(
            item.content,
            binascii.a2b_hex(item_encryption_key),
            binascii.a2b_hex(item_auth_key),
        )

    def create(self, item: Item, sync: bool = False):
        """Creates a new item on both the remote and local.

        :param item: The item to create
        :type item: Item
        :param sync: True if sync should occur immediately, defaults to False
        :param sync: bool, optional
        :raises ValueError:
            - When item is already synced
            - When item already exists locally
        """
        item_path = self._build_item_path(item)
        if self._item_synced(item):
            raise ValueError(f"item {item!r} already exists in sync")
        if self._item_exists(item):
            raise ValueError(f"item {item!r} already exists locally")
        self.items[item.uuid] = item
        with item_path.open("w") as stream:
            ujson.dump(item.to_dict(), stream)
        if sync:
            self.sync(items=[item])
        else:
            self._unsynced.append(item)

    def create_from(self, filepath: str, content_type: str, sync: bool = False) -> Item:
        """Creates a new item on both the remote and local from a file on the local.

        :param filepath: The filepath to add to the sync
        :type filepath: str
        :param content_type: The content type of the filepath
        :type content_type: str
        :param sync: True if sync should occur immediately, defaults to False
        :param sync: bool, optional
        :raises ValueError: When filepath does not exist
        :return: The created item
        :rtype: Item
        """
        filepath = Path(filepath)
        if not filepath.is_file():
            raise ValueError(f"no such file {filepath!r} exists")
        with filepath.open("r") as stream:
            created_item = self.encrypt(stream.read(), content_type)
            self.create(created_item)
            return created_item

    def delete(self, item: Item, sync: bool = False):
        """Deletes an item from the sync.

        :param item: The item to delete
        :type item: Item
        :param sync: True if sync should occur immediately, defaults to False
        :param sync: bool, optional
        :raises ValueError:
            - When the item is not currently synced
            - When the item does not exist locally
        """
        item_path = self._build_item_path(item)
        if not self._item_synced(item):
            raise ValueError(f"no such item {item!r} is currently synced")
        if not self._item_exists(item):
            raise ValueError(f"no such item {item!r} exists locally")
        self.items[item.uuid].deleted = True
        item_path.unlink()
        if sync:
            self.sync(items=[item])
        else:
            self._unsynced.append(item)

    def update(self, item: Item, sync: bool = False):
        """Updates the content of an existing item to the remote.

        :param item: The item to update
        :type item: Item
        :param sync: True if sync should occur immediately, defaults to False
        :param sync: bool, optional
        :raises ValueError:
            - When the item is not currently synced
            - When the item does not exist locally
        """

        if not self._item_synced(item):
            raise ValueError(f"no such item {item!r} is currently synced")
        if not self._item_exists(item):
            raise ValueError(f"no such item {item!r} exists locally")
        if sync:
            self.sync(items=[item])
        else:
            self._unsynced.append(item)
