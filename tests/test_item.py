# Copyright (c) 2018 Stephen Bunn <stephen@bunn.io>
# MIT License <https://opensource.org/licenses/MIT>

from arrow import Arrow
from hypothesis import given
from hypothesis.strategies import (
    uuids,
    text,
    booleans,
    datetimes,
    one_of,
    none,
    composite,
    from_regex,
)
from hypothesis.extra.pytz import timezones

from standardfile.item import Item, String

VERSION_REGEX = r"\d{3}"
UUID_REGEX = (
    r"[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}"
)
BASE64_REGEX = r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
HASH_REGEX = r"[a-f0-9]{16,32}"
VALID_STRING_REGEX = r":".join(
    [VERSION_REGEX, BASE64_REGEX, UUID_REGEX, HASH_REGEX, BASE64_REGEX]
)

@composite
def item_dict(draw):
    return dict(
        uuid=str(draw(uuids())),
        content=draw(one_of(none(), text(), from_regex(VALID_STRING_REGEX))),
        content_type=draw(text()),
        enc_item_key=draw(one_of(none(), text(), from_regex(VALID_STRING_REGEX))),
        deleted=draw(booleans()),
        created_at=draw(datetimes(timezones=timezones())).isoformat(),
        updated_at=draw(datetimes(timezones=timezones())).isoformat(),
        auth_hash=draw(one_of(none(), text())),
    )

@composite
def string_pair(draw):
    string_dict = dict(
        version=draw(from_regex(VERSION_REGEX)),
        auth_hash=draw(from_regex(HASH_REGEX)),
        uuid=str(draw(uuids())),
        iv=draw(from_regex(HASH_REGEX)),
        cipher_text=draw(from_regex(BASE64_REGEX))
    )
    return ":".join([
        string_dict["version"],
        string_dict["auth_hash"],
        string_dict["uuid"],
        string_dict["iv"],
        string_dict["cipher_text"]
    ]), string_dict


@given(item_dict())
def test_item_from_dict(resp):
    """Tests building Item objects from item dictionary.
    """
    item = Item.from_dict(resp)
    assert isinstance(item, Item)
    assert item.uuid == resp["uuid"]
    assert item.content_type == resp["content_type"]
    assert item.deleted == resp["deleted"]
    assert item.auth_hash == resp["auth_hash"]

    assert isinstance(item.created_at, Arrow)
    assert item.created_at.isoformat() == resp["created_at"]
    assert isinstance(item.updated_at, Arrow)
    assert item.updated_at.isoformat() == resp["updated_at"]

    if isinstance(resp["enc_item_key"], str) and len(resp["enc_item_key"]) > 0:
        if String.is_valid(resp["enc_item_key"]):
            assert isinstance(item.enc_item_key, String)
            if String.is_valid(resp["content"]):
                assert isinstance(item.content, String)
            else:
                assert item.content is resp["content"]
        else:
            assert item.enc_item_key is resp["enc_item_key"]

@given(item_dict())
def test_item_to_dict(resp):
    """Tests Item object to symmetric dictionary.
    """
    item = Item.from_dict(resp)
    assert item.to_dict() == resp


@given(string_pair())
def test_string_from_string(resp):
    """Tests building String objects from strings.
    """
    (string_str, string_dict) = resp
    string = String.from_string(string_str)
    assert isinstance(string, String)
    assert string.version == string_dict["version"]
    assert string.auth_hash == string_dict["auth_hash"]
    assert string.uuid == string_dict["uuid"]
    assert string.iv == string_dict["iv"]
    assert string.cipher_text == string_dict["cipher_text"]


@given(string_pair())
def test_string_to_string(resp):
    """Tests String object to symmetric string.
    """
    (string_str, _) = resp
    string = String.from_string(string_str)
    assert isinstance(string, String)
    assert string.to_string() == string_str


@given(string_pair())
def test_string_is_valid(resp):
    """Tests valid strings.
    """
    (string_str, _) = resp
    assert String.is_valid(string_str)


@given(one_of(none(), text().filter(lambda x: x.count(":") != 4)))
def test_string_not_is_valid(string):
    """Tests invalid strings.
    """
    assert not String.is_valid(string)
