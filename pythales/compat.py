import Crypto.Cipher.DES
import Crypto.Cipher.DES3

def patch_pycryptodome():
    """
    Patch PyCryptodome to maintain backward compatibility with legacy PyCrypto behavior
    used by pythales and pynblock.
    """
    # 1. Default mode for DES.new to MODE_ECB if omitted (pynblock/tools.py omits mode)
    try:
        Crypto.Cipher.DES.new(b'12345678')
    except TypeError:
        _orig_des_new = Crypto.Cipher.DES.new
        def _compat_des_new(key, mode=Crypto.Cipher.DES.MODE_ECB, *args, **kwargs):
            return _orig_des_new(key, mode, *args, **kwargs)
        Crypto.Cipher.DES.new = _compat_des_new

    # 2. Allow 3DES keys that degenerate to single DES (e.g. 16-byte keys with K1 == K2)
    _orig_des3_new = Crypto.Cipher.DES3.new
    if getattr(_orig_des3_new, '__name__', '') != '_compat_des3_new':
        def _compat_des3_new(key, mode=Crypto.Cipher.DES3.MODE_ECB, *args, **kwargs):
            try:
                return _orig_des3_new(key, mode, *args, **kwargs)
            except ValueError as e:
                if "Triple DES key degenerates to single DES" in str(e):
                    if len(key) == 16:
                        return Crypto.Cipher.DES.new(key[:8], mode, *args, **kwargs)
                    elif len(key) == 24:
                        k1, k2, k3 = key[:8], key[8:16], key[16:24]
                        if k1 == k2:
                            return Crypto.Cipher.DES.new(k3, mode, *args, **kwargs)
                        else:
                            return Crypto.Cipher.DES.new(k1, mode, *args, **kwargs)
                raise
        Crypto.Cipher.DES3.new = _compat_des3_new

patch_pycryptodome()
