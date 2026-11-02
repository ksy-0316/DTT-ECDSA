"""Hash functions, hashed EC-ElGamal and plain ECDSA (Section II of the paper).

EC-ElGamal (Section II-C) is used by the TMC to ship the confidential session
parameters of Protocol 2:

    T0 = kappa * G
    T1 = (t || gamma) XOR H(kappa * pkR)     -> RSU
    T2 = (t || gamma) XOR H(kappa * pkTr)    -> Tracer

Decryption exploits ``sk * T0 = sk * (kappa * G) = kappa * pk``.  The ephemeral
point T0 is shared by the two recipients, which is the standard multi-recipient
key-encapsulation pattern discussed in Section V-F.

Plain ECDSA (Section II-B) is used twice: for the proof of possession free
variant of the outer layer, i.e. the IEEE 1609.2 SignedData encapsulation that
the RSU produces under skR (Protocol 3, line 9 and assumption A5(iv)).
"""

from __future__ import annotations

import hashlib

from . import curve
from .curve import Q, mul_G, point_to_bytes

T_BYTES = 4                     # threshold value t
S_BYTES = curve.SCALAR_BYTES    # gamma

#: plaintext of both T1 and T2 is the string (t || gamma) = 36 bytes
TG_LEN = T_BYTES + S_BYTES


def H(*chunks: bytes) -> bytes:
    h = hashlib.sha256()
    for c in chunks:
        h.update(c)
    return h.digest()


def hash_to_scalar(*chunks: bytes) -> int:
    """c = H(sid || m) reduced into Z_q."""
    return int.from_bytes(H(*chunks), "big") % Q


def kdf(shared_point, length: int) -> bytes:
    """SHA-256 in counter mode, stretched to ``length`` bytes."""
    out = b""
    ctr = 0
    seed = point_to_bytes(shared_point)
    while len(out) < length:
        out += H(seed, ctr.to_bytes(4, "big"))
        ctr += 1
    return out[:length]


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# --------------------------------------------------------------------------- #
# (t || gamma) packing
# --------------------------------------------------------------------------- #
def pack_t_gamma(t: int, gamma: int) -> bytes:
    return t.to_bytes(T_BYTES, "big") + gamma.to_bytes(S_BYTES, "big")


def unpack_t_gamma(blob: bytes):
    t = int.from_bytes(blob[:T_BYTES], "big")
    gamma = int.from_bytes(blob[T_BYTES:T_BYTES + S_BYTES], "big")
    return t, gamma


# --------------------------------------------------------------------------- #
# Hashed EC-ElGamal
# --------------------------------------------------------------------------- #
def ecelgamal_encrypt(pk, kappa: int, plaintext: bytes) -> bytes:
    """Return the ciphertext component c2; c1 = T0 = kappa * G is shared."""
    return _xor(plaintext, kdf(curve.scalar_mul(kappa, pk), len(plaintext)))


def ecelgamal_decrypt(sk: int, T0, c2: bytes) -> bytes:
    return _xor(c2, kdf(curve.scalar_mul(sk, T0), len(c2)))


# --------------------------------------------------------------------------- #
# Plain ECDSA over secp256r1 (Section II-B)
# --------------------------------------------------------------------------- #
#: (r, s) encoded as two 32-byte scalars -- the 64-byte tag counted in |sigma|
ECDSA_TAG_BYTES = 2 * curve.SCALAR_BYTES


def ecdsa_sign(sk: int, msg: bytes):
    """sigma = (r, s) with s = k^-1 (e + sk * r) mod q."""
    e = hash_to_scalar(msg)
    while True:
        k = curve.rand_scalar()
        R = mul_G(k)
        r = R[0] % Q
        if r == 0:
            continue
        s = curve.inv_mod_q(k) * (e + sk * r) % Q
        if s != 0:
            return r, s


def ecdsa_verify(pk, msg: bytes, sig) -> bool:
    """Accept iff the abscissa of u1 * G + u2 * pk equals r."""
    r, s = sig
    if not (1 <= r < Q and 1 <= s < Q):
        return False
    e = hash_to_scalar(msg)
    w = curve.inv_mod_q(s)
    u1 = e * w % Q
    u2 = r * w % Q
    point = curve.point_add(mul_G(u1), curve.scalar_mul(u2, pk))
    if point is None:
        return False
    return point[0] % Q == r
