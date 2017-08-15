""" SecureConfigExceptions.
"""

class SecureConfigException(Exception):
    """ SecureConfigExceptions.
    """

    def __init__(self, message, errors=None):
        Exception.__init__(self, message)
        self.errors = errors

class ReadOnlyConfigError(SecureConfigException):
    """ Thrown if the configuration is read-only.
    """

    pass
