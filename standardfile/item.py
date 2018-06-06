# Copyright (c) 2018 Stephen Bunn <stephen@bunn.io>
# MIT License <https://opensource.org/licenses/MIT>

import enum
from typing import Any, Generic, TypeVar

import attr
import arrow

T_String = TypeVar("String")
T_Item = TypeVar("Item")


@attr.s
class String(Generic[T_String]):
    """Defines a Standard File string.
    """

    version = attr.ib(type=str)
    auth_hash = attr.ib(type=str, repr=False)
    uuid = attr.ib(type=str)
    iv = attr.ib(type=str, repr=False)
    cipher_text = attr.ib(type=str, repr=False)

    @classmethod
    def is_valid(cls, string: str) -> bool:
        """Check if a given string is valid.

        :param string: The string the check
        :type string: str
        :return: True if valid, otherwise False
        :rtype: bool
        """
        return isinstance(string, str) and len(string) > 0 and string.count(":") == 4

    @classmethod
    def from_string(cls, string: str) -> T_String:
        """Creates an instance from a string.

        :param string: The string to create an instance from
        :type string: str
        :return: An instance of ``String``
        :rtype: T_String
        """
        if cls.is_valid(string):
            return cls(*string.split(":"))

    def to_string(self) -> str:
        """Writes string out to a dictionary.

        :return: The resulting string
        :rtype: str
        """
        return ":".join(
            [self.version, self.auth_hash, self.uuid, self.iv, self.cipher_text]
        )


@attr.s
class Item(Generic[T_Item]):
    """Defines a Standard File item.

    Defined by StandardFile at `<https://standardfile.org/#items>`__.
    """

    uuid = attr.ib(type=str)
    content = attr.ib(type=str, repr=False)
    content_type = attr.ib(type=str, repr=False)
    enc_item_key = attr.ib(type=str, repr=False)
    deleted = attr.ib(type=bool, repr=False)
    created_at = attr.ib(type=str, converter=arrow.get, repr=False)
    updated_at = attr.ib(type=str, converter=arrow.get, repr=False)
    auth_hash = attr.ib(type=str, default=None, repr=False)

    def __attrs_post_init__(self):
        """Initializes class attributes after initial initialization.
        """

        self.enc_item_key = (
            String.from_string(self.enc_item_key)
            if String.is_valid(self.enc_item_key)
            else self.enc_item_key
        )
        self.content = (
            String.from_string(self.content)
            if String.is_valid(self.content) and isinstance(self.enc_item_key, String)
            else self.content
        )

    @classmethod
    def from_dict(cls, item_dict: dict) -> T_Item:
        """Creates an instance from a dictionary.

        :param item_dict: The dictionary to create an item from
        :type item_dict: dict
        :return: An instance of ``Item``
        :rtype: T_Item
        """
        if isinstance(item_dict, dict) and len(item_dict) > 0:
            return cls(**item_dict)

    def to_dict(self) -> dict:
        """Writes item out to a dictionary.

        :return: The resulting dictionary
        :rtype: dict
        """
        retn = attr.asdict(self)
        retn.update(
            dict(
                created_at=self.created_at.isoformat(),
                updated_at=self.updated_at.isoformat(),
            )
        )
        if isinstance(self.content, String):
            retn["content"] = self.content.to_string()
        if isinstance(self.enc_item_key, String):
            retn["enc_item_key"] = self.enc_item_key.to_string()

        return retn
