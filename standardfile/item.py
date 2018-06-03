# Copyright (c) 2018 Stephen Bunn <stephen@bunn.io>
# MIT License <https://opensource.org/licenses/MIT>

import enum
from typing import Any, Generic, TypeVar

import attr
import arrow


T_String = TypeVar("String")
T_Item = TypeVar("Item")


class ContentType(enum.Enum):
    """The various content types an item can have.
    """

    UNKNOWN = None
    NOTE = "Note"
    TAG = "Tag"
    EXTENSION = "Extension"
    SF_MFA = "SF|MFA"
    SF_Extension = "SF|Extension"
    SN_COMPONENT = "SN|Component"
    SN_THEME = "SN|Theme"
    SN_USER_PREFERENCES = "SN|UserPreferences"


@attr.s
class String(Generic[T_String]):
    """Defines a Standard File string.
    """

    version = attr.ib(type=str)
    auth_hash = attr.ib(type=str)
    uuid = attr.ib(type=str)
    iv = attr.ib(type=str)
    cipher_text = attr.ib(type=str)

    @classmethod
    def from_string(cls, string: str) -> T_String:
        """Creates an instance from a string.

        :param string: The string to create an instance from
        :type string: str
        :return: An instance of ``String``
        :rtype: T_String
        """
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
    content_type = attr.ib(type=str, converter=ContentType, repr=False)
    enc_item_key = attr.ib(type=str, repr=False)
    deleted = attr.ib(type=bool, repr=False)
    created_at = attr.ib(type=str, converter=arrow.get, repr=False)
    updated_at = attr.ib(type=str, converter=arrow.get, repr=False)
    auth_hash = attr.ib(type=str, default=None, repr=False)

    @classmethod
    def from_dict(cls, item_dict: dict) -> T_Item:
        """Creates an instance from a dictionary.

        :param item_dict: The dictionary to create an item from
        :type item_dict: dict
        :return: An instance of ``Item``
        :rtype: T_Item
        """
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
                content_type=self.content_type.value,
            )
        )
        return retn
