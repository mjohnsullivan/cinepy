import os.path
from ctypes import CDLL, c_char_p

MODULE_PATH = os.path.dirname(__file__)

def thumbprint(pem):
    """
    Returns the certificate thumbprint from
    a standard PEM string
    """
    c_thumb_lib = CDLL(os.path.join(MODULE_PATH, '..', 'cinepy.so'))
    c_thumb_lib.calc_thumbprint_from_string.restype = c_char_p;
    return c_thumb_lib.calc_thumbprint_from_string(pem, len(pem))

if __name__ == '__main__':
    with open('cert.pem', 'r') as f:
        print 'Thumbprint: %s' % thumbprint(f.read())
