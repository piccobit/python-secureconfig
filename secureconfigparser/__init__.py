from pkgutil import extend_path
__path__ = extend_path(__path__, __name__)

__author__ = 'nthmost'

from .baseclass import SecureConfig
from .secureconfigparser import SecureConfigParser
