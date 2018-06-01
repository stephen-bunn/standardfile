# Copyright (c) 2018 Stephen Bunn <stephen@bunn.io>
# MIT License <https://opensource.org/licenses/MIT>

import abc

from requests import Session

import ujson

from . import constants, exceptions


class StandardFileObject(abc.ABC):
    """Standard File object superclass.
    """

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

    def _make_request(cls, method: str, endpoint: str, **kwargs) -> dict:
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
        response = getattr(cls.session, method)(endpoint, **kwargs)
        result = ujson.loads(response.text)
        if response.status_code != 200:
            cls._handle_error(result.get("error"))
        return result
