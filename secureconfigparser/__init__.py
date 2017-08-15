""" SecureConfigParser Package Init.
"""

from pkgutil import extend_path

__path__ = extend_path(__path__, __name__)

from .baseclass import SecureConfig
from .secureconfigparser import SecureConfigParser
