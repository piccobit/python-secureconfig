""" CryptKeeper pattern:

 - location possibilities: file, env, string
 - schemes: symmetric (AES) via Fernet [future: asymmetric (RSA)]
 - actions: load, store, encrypt, decrypt.

Notes:

Assume "aspirational" invocation of StorageCryptKeeper unless
kwargs['proactive'] == False
(i.e. if supplied file path or env variable doesn't exist, create it.)

FileCryptKeeper will not create a directory, only a file. Target directory must exist.

The 'sigil' attribute is being used in SecureConfigParser to distinguish an encrypted
value from a plaintext value.  It could be used in the future to allow multiple keys
to encrypt and decrypt values from the same config.

CryptKeeper is built around cryptography.io which asserts the following
standards about its "Fernet" protocol:

      * AES in CBC mode with a 128-bit key for encryption; using PKCS7 padding.
      * HMAC using SHA256 for authentication.
      * Initialization vectors are generated using os.urandom().
"""


import os

from cryptography.fernet import Fernet


def verify_key(key, teststr='test string'):
    """ See if key can be used to encrypt and decrypt successfully.
    """

    ck = CryptKeeper(key)  # pylint: disable=invalid-name

    try:
        enctxt = ck.encrypt(teststr)
        #print(enctxt)
        assert teststr == ck.decrypt(enctxt)
    except Exception as exception:  # pylint: disable=broad-except
        print(exception)

    return False

class CryptKeeperAccessMethods(object):
    """ Not to be used directly; subclass to make objects with
        a standardized array of encryption classmethods based on
        what's available in cryptkeeper.
    """

    @classmethod
    def from_env(cls, keyenv, *args, **kwargs):
        """ Required argument: keyenv (name of environment variable).
        """

        kwargs['ck'] = EnvCryptKeeper(keyenv)
        return cls(*args, **kwargs)

    @classmethod
    def from_file(cls, keyloc, *args, **kwargs):
        """ Required argument: keyloc (path to file containing key).
        """

        kwargs['ck'] = FileCryptKeeper(keyloc)
        return cls(*args, **kwargs)

    @classmethod
    def from_key(cls, key, *args, **kwargs):
        """ Required argument: key (string containing key).
        """

        kwargs['ck'] = CryptKeeper(key=key)
        return cls(*args, **kwargs)


class CryptKeeper(object):
    """ TODO
    """

    sigil_base = 'CK_%s::'

    @classmethod
    def generate_key(cls):
        """ TODO
        """

        return Fernet.generate_key()

    def __init__(self, *args, **kwargs):  # pylint: disable=unused-argument
        """ Base CryptKeeper class. Supply key=string to provide key,
            or allow CryptKeeper to generate a new key when instantiated
            without arguments.
        """

        self.key = kwargs.get('key', None)
        self.sigil = kwargs.get('sigil', self.sigil_base % 'FERNET')

        # if proactive==True, create new key and store it.
        # Appropriate Exception will be raised if store() not possible.

        self.proactive = kwargs.get('proactive', True)

        if self._key_exists():
            self.key = self.load()
            self.key = self._clean_key(self.key)
            self.crypter = Fernet(self.key)
        elif self.proactive:
            self.key = self._gen_key()
            self.crypter = Fernet(self.key)
            self.store()
        else:
            raise Exception('no key supplied or key location does not exist')

    def _key_exists(self):
        'override for key storage based classes'
        if self.key:
            return True

    def _clean_key(self, key):  # pylint: disable=no-self-use
        """ Ensures a key free of surrounding whitespace and newlines.
        """

        return key.strip()

    def _gen_key(self):  # pylint: disable=no-self-use
        """ Generates a new Fernet-based encryption key.
        """

        return Fernet.generate_key()

    def encrypt(self, inp):  # pylint: disable=no-self-use
        """ Takes plaintext string and returns encrypted string.
        """

        return self.crypter.encrypt(inp)

    def decrypt(self, inp):
        """ Takes encrypted string and returns plaintext string.
        """

        return self.crypter.decrypt(inp)

    def store(self):
        """ Override for key storage based classes.
        """

        pass

    def load(self):
        """ Override for key storage based classes.
        """

        return self.key



class EnvCryptKeeper(CryptKeeper):
    """ Loads a key from env.  If proactive==True (default: False) and no key is
    present at env, EnvCryptKeeper creates a key for you at this environment
    variable.
    """

    def __init__(self, env, *args, **kwargs):
        self.env = env
        super(EnvCryptKeeper, self).__init__(*args, **kwargs)

    def _key_exists(self):
        return os.environ.get(self.env, None)

    def store(self):
        'store currently active key into environment variable'
        os.environ[self.env] = self.key
        os.putenv(self.env, self.key)

    def load(self):
        'retrieve key from environment variable'
        return os.environ[self.env]


class FileCryptKeeper(CryptKeeper):
    """ Loads a key from supplied path.

    If proactive==True (default: False) and file cannot be loaded at
    supplied path, FileCryptKeeper creates this file to store key within.

    If directory cannot be written to, FileCryptKeeper raises OSError
    (i.e. it will not also try to create a directory.)

    Supply paranoid=False to turn off directory permission checks.
    (DANGER, WILL ROBINSON!)
    """

    def __init__(self, path, *args, **kwargs):

        self.path = path
        self.paranoid = kwargs.get('paranoid', True)
        super(FileCryptKeeper, self).__init__(*args, **kwargs)

    def _key_exists(self):
        # if self.paranoid:
        #   check permissions on file and path.
        #   if sketchy, raise Exception informing user of sketchiness.
        return os.path.exists(self.path)

    def store(self):
        'store currently active key into file at self.path'
        open(self.path, 'wb').write(self.key)

    def load(self):
        'retrieve key from file at self.path (supplied at instantiation)'
        return open(self.path, 'rb').read()
