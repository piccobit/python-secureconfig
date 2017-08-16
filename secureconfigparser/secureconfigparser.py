"""

SecureConfigParser.

SECURECONFIG pattern:
 - allow key retrieval and storage from CryptKeeper object
 - default to symmetric keys using AES (via Fernet)
 - (future) provide asymmetric encryption using RSA

SECURECONFIGPARSER pattern:
 - read list of files
 - read and interpolate vars
 - has .ck attribute -> CryptKeeper object


GLOSSARY OF VARIABLE NAMES

sec == section
ck = CryptKeeper object

ConfigParser is an "old style" class, so we're using old-style calls to super
until ConfigParser gets its act together.

oh god multiple inheritance
/me crosses her fingers

"""

import logging
import sys

from configparser import ConfigParser, NoSectionError, NoOptionError

from .baseclass import CryptKeeperAccessMethods


_LOGGER = logging.getLogger(__name__)
_LOGGER.setLevel(logging.DEBUG)
_LOGFORMATTER = logging.Formatter(
    "%(asctime)s,%(msecs)d %(levelname)-8s [%(threadName)-12.12s] "
    "[%(filename)s:%(lineno)d] %(message)s")
_LOGGER.propagate = True
_CH = logging.StreamHandler(sys.stdout)
_CH.setFormatter(_LOGFORMATTER)
_LOGGER.addHandler(_CH)


class SecureConfigParser(ConfigParser, CryptKeeperAccessMethods):
    """ A subclass of ConfigParser py:class::ConfigParser which decrypts
    certain entries.
    """

    def __init__(self, *args, **kwargs):

        # supplied by cryptkeeper_access_methods
        self.ck = kwargs.pop('ck', None)  # pylint: disable=invalid-name

        ConfigParser.__init__(self, *args, **kwargs)

    def read(self, filenames):
        """ Read the list of config files.
        """

        _LOGGER.debug("filenames: %s", filenames)
        ConfigParser.read(self, filenames)

    def raw_get(self, sec, key, default=None):
        """ Get the raw value without decoding it.
        """

        _LOGGER.debug("sec: %s, key: %s", sec, key)

        try:
            return ConfigParser.get(self, sec, key, raw=True)
            # return super(SecureConfigParser, self).get(sec, key)
        except (NoSectionError, NoOptionError):
            return default
        # pylint: disable=broad-except,unused-variable
        except Exception as exception:
            _LOGGER.debug("%s", exception)

    def raw_set(self, sec, key, val):
        """ Set the value without encrypting it.
        """

        return ConfigParser.set(self, sec, key, val)

    def raw_items(self, sec):
        """ Return the items in a section without decrypting the values.
        """

        return ConfigParser.items(self, sec)

    def val_decrypt(self, raw_val):
        """ Decrypt supplied value if it appears to be encrypted.
        """

        # pylint: disable=no-else-return
        if self.ck and raw_val.startswith(self.ck.sigil):
            return self.ck.crypter.decrypt(
                raw_val.split(self.ck.sigil)[1].encode())
        else:
            return raw_val

    def get(self, sec, key, default=None):
        """ Get the value from the config, possibly decrypting it.
        """

        raw_val = self.raw_get(sec, key)
        if raw_val is None:
            return default

        val = self.val_decrypt(raw_val)

        return val

    def set(self, sec, key, new_val, encrypt=False):
        """ If the value should be secured, encrypt and update it;
            Otherwise just update it.
        Supply encrypt=True to encrypt a value that was not previously
        encrypted.
        """

        if not self.has_option(sec, key):
            if encrypt:
                new_val = self.ck.sigil + self.ck.encrypt(new_val).decode()
            return self.raw_set(sec, key, new_val)

        old_raw_val = self.raw_get(sec, key)

        if old_raw_val.startswith(self.ck.sigil) or encrypt:
            new_val = self.ck.sigil + self.ck.encrypt(new_val).decode()
            return self.raw_set(sec, key, new_val)

        return self.raw_set(sec, key, new_val)

    def items(self, sec):
        """ Iterate over the items; decoding the values.
        """

        for (key, val) in self.raw_items(sec):
            val = self.val_decrypt(val)
            yield (key, val)

    def print_decrypted(self):
        """ Print the file with all the values decrypted.
        """

        for sec in self.sections():
            print("[%s]" % sec)
            for (key, val) in self.items(sec):
                print("%s=%s" % (key, val))
            print()
