# Copyright (c) 2018 Stephen Bunn <stephen@bunn.io>
# MIT License <https://opensource.org/licenses/MIT>

import enum

import attr


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
