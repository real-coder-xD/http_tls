"""Exceptions compatible with requests.exceptions."""

class RequestException(IOError):
    def __init__(self, *args, **kwargs):
        self.response = kwargs.pop("response", None)
        super().__init__(*args, **kwargs)

class HTTPError(RequestException):
    """An HTTP error occurred."""

class ConnectionError(RequestException):
    """A Connection error occurred."""

class Timeout(RequestException):
    """The request timed out."""

class ConnectTimeout(Timeout, ConnectionError):
    """The request timed out while trying to connect to the remote server."""

class ReadTimeout(Timeout):
    """The server did not send any data in the allotted amount of time."""

class SSLError(ConnectionError):
    """An SSL error occurred."""

class TooManyRedirects(RequestException):
    """Too many redirects."""
