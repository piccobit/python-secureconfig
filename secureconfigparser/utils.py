""" SecureConfigParser Utils

All ck_obj arguments refer to instances of
CryptKeeper objects (and subclass objects).
"""

import string

from random import choice

# all ck_obj arguments refer to instances of
# CryptKeeper objects (and subclass objects)

ACCEPTED_SYMBOLS = '_-)(&^#@!.'

def safe_pwgen(length=32, symbols=ACCEPTED_SYMBOLS):
    """ Returns a non-human-readable password of length=length (default 32).

    :param length: (int) desired length of password (default: 32)
    :param symbols: non-alphanumeric symbols to accept as part of the password.
            default ACCEPTED_SYMBOLS=  _-)(&^#@!.
    """

    chars = string.ascii_letters + string.digits + symbols
    return ''.join(choice(chars) for _ in range(length))

def encrypt_file(ck_obj, infile, outfile):
    """ TODO.
    """

    enctxt = ck_obj.encrypt(open(infile, 'r').read())
    file = open(outfile, 'wb')
    file.write(enctxt)
    file.close()

def decrypt_file(ck_obj, infile, outfile=''):
    """ TODO.
    """

    txt = ck_obj.decrypt(open(infile, 'rb').read())
    if outfile:  # pylint: disable=no-else-return
        file = open(outfile, 'w')
        file.write(txt)
        file.close()
        return outfile
    else:
        return txt
