# Copyright (c) 2018 Stephen Bunn <stephen@bunn.io>
# MIT License <https://opensource.org/licenses/MIT>


class StandardFileException(Exception):
    """The parent exception of all custom Standard File exceptions.
    """

    def __init__(self, message: str, data: dict = {}):
        """Initializes the custom exception.

        :param message: A custom exception message
        :type message: str
        :param data: A data container for the exception, defaults to {}
        :param data: dict, optional
        """
        self.message = message
        self.data = data
        super().__init__(self.message)


class AuthException(StandardFileException):
    """The exception namespace for all authentication based exceptions.
    """

    pass


class AuthRequired(AuthException):
    """Raised when authentication is required but not provided.
    """

    pass


class AuthInvalid(AuthException):
    """Raised when authentication is invalid.
    """

    pass


class MFARequired(AuthException):
    """Raised when multifactor authentication is required but not provided.
    """

    pass


class MFAInvalid(AuthException):
    """Raised when the provided multifactor authentication is invalid.
    """

    pass


EXCEPTION_MAPPING = {"mfa-invalid": MFAInvalid, "mfa-required": MFARequired}
