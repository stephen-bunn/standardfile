# Copyright (c) 2018 Stephen Bunn <stephen@bunn.io>
# MIT License <https://opensource.org/licenses/MIT>

import hmac
import base64
import hashlib
import secrets
import binascii

import attr
from Crypto.Cipher import AES

from . import exceptions
from .item import Item, String
from .auth import UserAuth


@attr.s
class Cryptographer(object):
    """The cryptographer class namespace.
    """

    preferred_version = "002"

    @classmethod
    def _unpad(cls, content: bytes) -> bytes:
        """Unpad a AES decrypted content.

        :param content: The content to unpad
        :type content: bytes
        :return: Unpadded content
        :rtype: bytes
        """
        return content[: -ord(content[len(content) - 1 :])]

    @classmethod
    def _pad(cls, content: bytes) -> bytes:
        """Pad a AES encrypted content.

        :param content: The content to pad
        :type content: bytes
        :return: Padded content
        :rtype: bytes
        """
        block_padding = AES.block_size - len(content) % AES.block_size
        return content + (chr(block_padding) * block_padding).encode()

    @classmethod
    def _encryption_type2(
        cls,
        content: str,
        uuid: str,
        version: str,
        encryption_key: bytes,
        auth_key: bytes,
    ) -> String:
        """Encrypt using the second type of encryption for some content.
        """
        iv = secrets.token_bytes(128 // 8)
        string_iv = binascii.b2a_hex(iv).decode()
        cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
        cipher_text = base64.b64encode(
            cipher.encrypt(cls._pad(content.encode()))
        ).decode()
        auth_hash = hmac.new(
            auth_key,
            msg=":".join([version, uuid, string_iv, cipher_text]).encode(),
            digestmod=hashlib.sha256,
        ).hexdigest()
        return String.from_string(
            ":".join([version, auth_hash, uuid, string_iv, cipher_text])
        )

    @classmethod
    def _decryption_type2(
        cls, string: String, encryption_key: bytes, auth_key: bytes
    ) -> str:
        """Decrypt using for the second type of encryption for a string.
        """
        local_hash = hmac.new(
            auth_key,
            msg=":".join(
                [string.version, string.uuid, string.iv, string.cipher_text]
            ).encode(),
            digestmod=hashlib.sha256,
        ).hexdigest()
        if local_hash != string.auth_hash:
            raise exceptions.TamperDetected(
                (
                    f"local hash {local_hash!r} does not match string "
                    f"authentication hash {string.auth_hash!r}"
                )
            )

        cipher = AES.new(encryption_key, AES.MODE_CBC, binascii.a2b_hex(string.iv))
        return cls._unpad(cipher.decrypt(base64.b64decode(string.cipher_text))).decode()

    @classmethod
    def _decrypt_002(
        cls, string: String, encryption_key: bytes, auth_key: bytes
    ) -> str:
        """Decryption version 002 of a string.
        """
        return cls._decryption_type2(string, encryption_key, auth_key)

    @classmethod
    def _encrypt_002(
        cls, content: str, uuid: str, encryption_key: bytes, auth_key: bytes
    ) -> String:
        """Encryption version 002 of some content.
        """
        return cls._encryption_type2(content, uuid, "002", encryption_key, auth_key)

    @classmethod
    def _decrypt_003(
        cls, string: String, encryption_key: bytes, auth_key: bytes
    ) -> str:
        """Decryption version 003 of a string.
        """
        return cls._decryption_type2(string, encryption_key, auth_key)

    @classmethod
    def _encrypt_003(
        cls, content: str, uuid: str, encryption_key: bytes, auth_key: bytes
    ) -> String:
        """Encryption version 003 of some content.
        """
        return cls._encryption_type2(content, uuid, "003", encryption_key, auth_key)

    @classmethod
    def decrypt(cls, string: String, encryption_key: bytes, auth_key: bytes) -> str:
        """Decrypts a string using a encryption and authentication key.

        :param string: The string to decrypt
        :type string: String
        :param encryption_key: The encryption key to use
        :type encryption_key: bytes
        :param auth_key: The authentication key to use
        :type auth_key: bytes
        :raises ValueError: If the string version is not supported
        :return: The decrypted string
        :rtype: str
        """
        decrypter = getattr(cls, f"_decrypt_{string.version}", None)
        if not decrypter:
            raise ValueError(f"unsupported encryption version {string.version!r}")
        return decrypter(string, encryption_key, auth_key)

    @classmethod
    def encrypt(
        cls, content: str, uuid: str, encryption_key: bytes, auth_key: bytes
    ) -> String:
        """Encrypts a string using a encryption and authentication key.

        :param content: The content to encrypt
        :type content: str
        :param uuid: The desired uuid string of the new content
        :type uuid: str
        :param encryption_key: The encryption key to use
        :type encryption_key: bytes
        :param auth_key: The authentication key to use
        :type auth_key: bytes
        :raises ValueError: If the preferred version is not supported
        :return: The resulting string instance
        :rtype: String
        """
        encrypter = getattr(cls, f"_encrypt_{cls.preferred_version}", None)
        if not encrypter:
            raise ValueError(
                f"unsupported encryption version {cls.preferred_version!r}"
            )
        return encrypter(content, uuid, encryption_key, auth_key)
