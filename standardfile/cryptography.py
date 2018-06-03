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


@attr.s
class Cryptographer(object):
    """The cryptographer class namespace.
    """

    @staticmethod
    def _unpad(content: bytes) -> bytes:
        """Unpad a AES decrypted content.

        :param content: The content to unpad
        :type content: bytes
        :return: Unpadded content
        :rtype: bytes
        """
        return content[: -ord(content[len(content) - 1 :])]

    @staticmethod
    def _pad(content: bytes) -> bytes:
        """Pad a AES encrypted content.

        :param content: The content to pad
        :type content: bytes
        :return: Padded content
        :rtype: bytes
        """
        block_padding = AES.block_size - len(content) % AES.block_size
        return content + (chr(block_padding) * block_padding).encode()

    @staticmethod
    def _decrypt_001(string: String, encryption_key: bytes, auth_key: bytes) -> bytes:
        """Decrypt version 001 of a string.

        :param string: The string to decrypt
        :type string: String
        :param encryption_key: The encryption key to use
        :type encryption_key: bytes
        :param auth_key: The authentication key to use
        :type auth_key: bytes
        :raises NotImplementedError: Currently not implemented
        :return: The decrypted bytes
        :rtype: bytes
        """

        raise NotImplementedError()

    @staticmethod
    def _decrypt_002(string: String, encryption_key: bytes, auth_key: bytes) -> bytes:
        """Decryption version 002 of a string.

        :param string: The string to decrypt
        :type string: String
        :param encryption_key: The encryption key to use
        :type encryption_key: bytes
        :param auth_key: The authentication key to use
        :type auth_key: bytes
        :raises exceptions.TamperDetected: If locally computed hash doesn't match the
            string's authentication match
        :return: The decrypted bytes
        :rtype: bytes
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
        return Cryptographer._unpad(
            cipher.decrypt(base64.b64decode(string.cipher_text))
        ).decode()

    @staticmethod
    def _encrypt_002(
        content: str, uuid: str, encryption_key: bytes, auth_key: bytes
    ) -> String:
        """Encryption version 002 of some content.

        :param content: The content to encrypt
        :type content: str
        :param uuid: The uuid of the encryption
        :type uuid: str
        :param encryption_key: The encryption key to use
        :type encryption_key: bytes
        :param auth_key: The authentication key to use
        :type auth_key: bytes
        :return: The resulting encrypted String instance
        :rtype: String
        """
        iv = secrets.token_bytes(128 // 8)
        string_iv = binascii.b2a_hex(iv).decode()
        cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
        cipher_text = base64.b64encode(
            cipher.encrypt(Cryptographer._pad(content.encode()))
        ).decode()
        auth_hash = hmac.new(
            auth_key,
            msg=":".join(["002", uuid, string_iv, cipher_text]).encode(),
            digestmod=hashlib.sha256,
        ).hexdigest()
        return String.from_string(
            ":".join(["002", auth_hash, uuid, string_iv, cipher_text])
        )

    @staticmethod
    def parse_string(string: str) -> String:
        """Parses a string into a item's string.

        :param string: The string to parse
        :type string: str
        :return: The item string object
        :rtype: String
        """
        return String.from_string(string)

    @staticmethod
    def decrypt_string(string: String, encryption_key: bytes, auth_key: bytes) -> bytes:
        """Decrypts a string using a encryption and authentication key.

        :param string: The string to decrypt
        :type string: String
        :param encryption_key: The encryption key to use
        :type encryption_key: bytes
        :param auth_key: The authentication key to use
        :type auth_key: bytes
        :raises NotImplementedError: If the string version is not supported
        :return: The decrypted bytes
        :rtype: bytes
        """
        string_decrypter = getattr(Cryptographer, f"_decrypt_{string.version}", None)
        if not string_decrypter:
            raise NotImplementedError(
                f"unsupported encryption version {string.version!r}"
            )
        return string_decrypter(string, encryption_key, auth_key)

    @staticmethod
    def encrypt_string(
        content: str, uuid: str, encryption_key: bytes, auth_key: bytes
    ) -> String:
        """Encrypts a string using a encryption and authentication key.

        :raises NotImplementedError: Currently not supported
        """

        return Cryptographer._encrypt_002(content, uuid, encryption_key, auth_key)
