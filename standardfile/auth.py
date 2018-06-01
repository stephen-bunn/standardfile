# Copyright (c) 2018 Stephen Bunn <stephen@bunn.io>
# MIT License <https://opensource.org/licenses/MIT>

import attr


@attr.s
class AuthKeys(object):
    password_key = attr.ib(type=str)
    master_key = attr.ib(type=str)
    auth_key = attr.ib(type=str)
