"""The five entities of the DTT-ECDSA message-reporting framework.

    TA      - Trusted Authority         (root of trust, key distribution, registry)
    Vehicle - intelligent connected vehicle (signer, holds ski)
    TMC     - Traffic Management Center (dynamic threshold t, masks alpha/beta, Delta)
    RSU     - Road Side Unit            (aggregator, holds skc)
    Tracer  - tracing authority         (holds skt, runs Protocol 4)

The notation follows Table I of the paper:

    a_j = gamma*k_j + alpha_j        b_j = gamma*sk_j + beta_j
    A_j = alpha_j * G                B_j = beta_j * G
    sum(alpha_j) + Delta = 0         R = sum(R_j), a = sum(a_j) + Delta, b = sum(b_j)
    z   = a^-1 (gamma*c + b*r_x)     Vp = (b * gamma^-1) * G

Who learns what (assumption A5(ii)): beta_j never reaches the RSU and alpha_j
never reaches the Tracer.  The RSU only obtains {A_j} and the aggregate Delta,
the Tracer only obtains {B_j}.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from . import crypto, curve
from .curve import Q, mul_G, point_sum, point_to_bytes
from .search import exhaustive_subset_search, search_space


# --------------------------------------------------------------------------- #
# Wire structures
# --------------------------------------------------------------------------- #
@dataclass
class SignatureShare:
    """delta_j = (sid, m, j, R_j, a_j, b_j)   -- Protocol 2, line 8."""
    sid: bytes
    m: dict
    j: int
    R: tuple
    a: int
    b: int

    #: Section VI-C: |sid| + |G| + 2|Zq| = 16 + 64 + 64 = 144 bytes.  The
    #: message m was already announced when the session was opened and the
    #: temporary index j travels in the frame header, so neither is recounted.
    WIRE_BYTES = 16 + curve.POINT_BYTES + 2 * curve.SCALAR_BYTES


@dataclass
class AggregateSignature:
    """sigma = (R, sid, m, Vp, z)   -- Protocol 3, line 8."""
    R: tuple
    sid: bytes
    m: dict
    Vp: tuple
    z: int
    m_bytes: bytes = b""

    #: Section VI-C: |R| + |Vp| + |z| + |outer ECDSA tag| = 64+64+32+64 = 224 B
    WIRE_BYTES = 2 * curve.POINT_BYTES + curve.SCALAR_BYTES + crypto.ECDSA_TAG_BYTES

    def to_bytes(self) -> bytes:
        """Byte image signed by the RSU under skR (outer IEEE 1609.2 layer)."""
        return (self.sid + self.m_bytes + point_to_bytes(self.R)
                + point_to_bytes(self.Vp) + curve.int_to_bytes(self.z))


@dataclass
class SessionCiphertext:
    """(T0, T1, T2): the EC-ElGamal encrypted threshold, Protocol 2 line 2."""
    T0: tuple
    T1: bytes
    T2: bytes

    def rsu_bytes(self) -> int:      # (T0, T1) -> RSU
        return curve.POINT_BYTES + len(self.T1)

    def tracer_bytes(self) -> int:   # (T0, T2) -> Tracer
        return curve.POINT_BYTES + len(self.T2)


# --------------------------------------------------------------------------- #
# Vehicle
# --------------------------------------------------------------------------- #
@dataclass
class Vehicle:
    """Intelligent connected vehicle: holds ski, publishes pki."""

    vid: str
    plate: str
    sk: int = 0
    pk: tuple = None

    #: vid (8 B) + plate (16 B) + pki (64 B) submitted at registration
    REG_BYTES = 8 + 16 + curve.POINT_BYTES

    def keygen(self):
        """ski <- Zq ; pki = ski * G   (Protocol 1, lines 4-6)."""
        self.sk = curve.rand_scalar()
        self.pk = mul_G(self.sk)
        return self.pk

    def sign_share(self, sid: bytes, m: dict, j: int, gamma: int,
                   alpha_j: int, beta_j: int) -> SignatureShare:
        """Protocol 2, lines 5-8 -- the whole on-line workload of a signer.

        k_j <- Zq ; R_j = k_j * G ; a_j = gamma*k_j + alpha_j ;
        b_j = gamma*sk_j + beta_j ; delta_j = (sid, m, j, R_j, a_j, b_j)

        One fixed-base scalar multiplication and two modular multiply-and-add
        steps, i.e. a per-signer cost independent of both t and n.
        """
        k_j = curve.rand_scalar()
        R_j = mul_G(k_j)
        a_j = (gamma * k_j + alpha_j) % Q
        b_j = (gamma * self.sk + beta_j) % Q
        return SignatureShare(sid=sid, m=m, j=j, R=R_j, a=a_j, b=b_j)


# --------------------------------------------------------------------------- #
# TA - Trusted Authority
# --------------------------------------------------------------------------- #
class TA:
    """Root of trust: curve setup, RSU/Tracer key pairs, vehicle registry."""

    #: system parameters handed to every vehicle: G || q || pkR || pkTr
    SYSPARAM_BYTES = curve.POINT_BYTES + curve.SCALAR_BYTES + 2 * curve.POINT_BYTES

    def __init__(self, security_param: int = 128):
        self.security_param = security_param
        self.curve_name = curve.CURVE_NAME
        self.sk_R = 0
        self.pk_R = None
        self.sk_Tr = 0
        self.pk_Tr = None
        self.registry: list[Vehicle] = []   # registration order == vehicle index

    # -- Protocol 1, lines 1-3 ------------------------------------------- #
    def setup(self):
        """curve <- G(lambda); (skR, pkR) for the RSU; (skTr, pkTr) for the Tracer."""
        self.sk_R = curve.rand_scalar()
        self.pk_R = mul_G(self.sk_R)
        self.sk_Tr = curve.rand_scalar()
        self.pk_Tr = mul_G(self.sk_Tr)

    # -- Protocol 1, lines 4-6 ------------------------------------------- #
    def register(self, vehicle: Vehicle, proof) -> bool:
        """Certify pki after the proof-of-possession check of assumption A5(i).

        ``proof = (W, u)`` is a Schnorr proof of knowledge of ski; the TA
        accepts iff ``u * G == W + e * pki`` with ``e = H(pki || W)``.
        """
        if vehicle.pk is None or not curve.is_on_curve(vehicle.pk):
            return False
        W, u = proof
        e = crypto.hash_to_scalar(point_to_bytes(vehicle.pk), point_to_bytes(W))
        if mul_G(u) != curve.point_add(W, curve.scalar_mul(e, vehicle.pk)):
            return False
        self.registry.append(vehicle)
        return True

    # -- Protocol 1, lines 7-10 ------------------------------------------ #
    @property
    def public_keys(self):
        return [v.pk for v in self.registry]

    def public_key(self):
        """pk = (pk1, ..., pkn, pkTr, pkR)."""
        return (self.public_keys, self.pk_Tr, self.pk_R)

    def combine_key(self):
        """skc = (pk1, ..., pkn, pkTr, skR)  -- handed to the RSU."""
        return (self.public_keys, self.pk_Tr, self.sk_R)

    def trace_key(self):
        """skt = (pk1, ..., pkn, skTr, pkR)  -- handed to the Tracer."""
        return (self.public_keys, self.sk_Tr, self.pk_R)

    # -- accountability chain (Section V-E) ------------------------------- #
    def identify(self, indices):
        """Map the keys returned by Trace back to registered identities."""
        return [(i, self.registry[i].vid, self.registry[i].plate) for i in indices]

    # -- byte sizes used by the communication model ----------------------- #
    def skc_bytes(self):
        return (len(self.registry) * curve.POINT_BYTES
                + curve.POINT_BYTES + curve.SCALAR_BYTES)

    def skt_bytes(self):
        return (len(self.registry) * curve.POINT_BYTES
                + curve.SCALAR_BYTES + curve.POINT_BYTES)

    def pk_bytes(self):
        return len(self.registry) * curve.POINT_BYTES + 2 * curve.POINT_BYTES


# --------------------------------------------------------------------------- #
# TMC - Traffic Management Center
# --------------------------------------------------------------------------- #
class TMC:
    """Outputs the dynamic threshold t, the masks (alpha_j, beta_j) and Delta.

    The TMC is the only entity that knows the map ``temporary index j ->
    registered vehicle``, which is why assumption A1 forbids it to collude with
    an RSU (Theorem 2).
    """

    #: (sid, j, gamma, alpha_j, beta_j) delivered to one signer, confidentially
    PARAM_BYTES = 16 + 4 + 3 * curve.SCALAR_BYTES

    def __init__(self, pk_R, pk_Tr, rng=None):
        self.pk_R = pk_R
        self.pk_Tr = pk_Tr
        self.rng = rng
        self.kappa = 0
        self.gamma = 0
        self.t = 0
        self.admitted: list[int] = []        # admitted[j-1] = registration index
        self.alphas: dict[int, int] = {}     # j -> alpha_j
        self.betas: dict[int, int] = {}      # j -> beta_j

    # -- Protocol 2, lines 1-2 ------------------------------------------- #
    def open_session(self, t: int) -> SessionCiphertext:
        """Pick kappa, gamma and encrypt (t || gamma) for the RSU and the Tracer."""
        self.t = t
        self.kappa = curve.rand_scalar()
        self.gamma = curve.rand_scalar()
        blob = crypto.pack_t_gamma(t, self.gamma)
        T0 = mul_G(self.kappa)
        T1 = crypto.ecelgamal_encrypt(self.pk_R, self.kappa, blob)
        T2 = crypto.ecelgamal_encrypt(self.pk_Tr, self.kappa, blob)
        return SessionCiphertext(T0=T0, T1=T1, T2=T2)

    # -- Protocol 2, lines 3-4 ------------------------------------------- #
    def admit(self, indices):
        """Assign the temporary indices j = 1..t and sample the masks.

        ``indices`` are the registration indices of the vehicles admitted to
        the round.  j is a fresh label, independent of the real identity, so it
        leaks nothing about the vehicle (Section IV-B).
        """
        self.admitted = list(indices)
        self.alphas, self.betas = {}, {}
        A, B = [], []
        for j in range(1, len(self.admitted) + 1):
            alpha_j = curve.rand_scalar()
            beta_j = curve.rand_scalar()
            self.alphas[j] = alpha_j
            self.betas[j] = beta_j
            A.append(mul_G(alpha_j))          # A_j = alpha_j * G  -> RSU
            B.append(mul_G(beta_j))           # B_j = beta_j * G   -> Tracer
        return A, B

    def params_for(self, j: int):
        """(gamma, alpha_j, beta_j) sent to signer j over a confidential channel."""
        return self.gamma, self.alphas[j], self.betas[j]

    # -- Protocol 3, line 2: Delta <- Allocate ---------------------------- #
    def allocate_delta(self, js) -> int:
        """Delta = -sum_{j in received} alpha_j, so that sum(alpha_j) + Delta = 0.

        The RSU reports the set {j} of vehicles that actually submitted a share,
        which prevents a vehicle from collecting masks and then refusing to sign.
        """
        return (-sum(self.alphas[j] for j in js)) % Q

    # -- non-repudiation audit of Section V-E ----------------------------- #
    def audit_share(self, share: SignatureShare, pk_i, B_j) -> bool:
        """b_j * G == gamma * pk_j + B_j: an audit only TMC + Tracer can run."""
        lhs = mul_G(share.b)
        rhs = curve.point_add(curve.scalar_mul(self.gamma, pk_i), B_j)
        return lhs == rhs


# --------------------------------------------------------------------------- #
# RSU - Road Side Unit (aggregator)
# --------------------------------------------------------------------------- #
class RSU:
    """Holds skc = (pk1..pkn, pkTr, skR) and runs Protocol 3."""

    #: session announcement broadcast to every registered vehicle:
    #: sid (16 B) + H(m) (32 B) + request header (16 B)
    ANNOUNCE_BYTES = 16 + 32 + 16

    def __init__(self, combine_key):
        self.pks, self.pk_Tr, self.sk_R = combine_key
        self.t = 0
        self.gamma = 0
        self.A = []                  # {A_j} received from the TMC
        self.consistency_ok = None   # result of the test of Protocol 3, line 4

    def open_ciphertext(self, ct: SessionCiphertext):
        """EC-ElGamal decryption of (T0, T1) with skR -> (t, gamma)."""
        blob = crypto.ecelgamal_decrypt(self.sk_R, ct.T0, ct.T1)
        self.t, self.gamma = crypto.unpack_t_gamma(blob)
        return self.t, self.gamma

    def receive_masks(self, A):
        """{A_j} = {alpha_j * G} from the TMC (beta_j is never sent here)."""
        self.A = list(A)

    def submitted_indices(self, shares):
        """{j}: reported back to the TMC in order to obtain Delta."""
        return [s.j for s in shares]

    # -- Protocol 3 ------------------------------------------------------- #
    def combine(self, shares, m_bytes: bytes, delta: int):
        """Aggregate t shares into sigma and encapsulate it under skR.

        Returns ``(sigma, sig, consistency_ok)`` where ``sig`` is the outer
        IEEE 1609.2 ECDSA signature required by assumption A5(iv).
        """
        sid = shares[0].sid
        m = shares[0].m

        R = point_sum(s.R for s in shares)                 # R = sum R_j
        sum_a = sum(s.a for s in shares) % Q
        a = (sum_a + delta) % Q                            # a = sum a_j + Delta
        b = sum(s.b for s in shares) % Q                   # b = sum b_j

        # line 4: sum(a_j) * G == gamma * R + A -- rejects randomness that the
        # TMC did not distribute
        A_sum = point_sum(self.A)
        self.consistency_ok = (
            mul_G(sum_a) == curve.point_add(curve.scalar_mul(self.gamma, R), A_sum))

        c = crypto.hash_to_scalar(sid, m_bytes)            # c = H(sid || m)
        r_x = R[0] % Q                                     # abscissa of R
        z = curve.inv_mod_q(a) * (self.gamma * c + b * r_x) % Q
        V_p = mul_G(b * curve.inv_mod_q(self.gamma) % Q)   # Vp = (b/gamma) * G

        sigma = AggregateSignature(R=R, sid=sid, m=m, Vp=V_p, z=z, m_bytes=m_bytes)
        sig = crypto.ecdsa_sign(self.sk_R, sigma.to_bytes())
        return sigma, sig, self.consistency_ok

    def disclose_b(self, shares):
        """{(j, b_j)} handed to the Tracer when a message is challenged."""
        return [(s.j, s.b) for s in shares]


# --------------------------------------------------------------------------- #
# Tracer
# --------------------------------------------------------------------------- #
@dataclass
class TraceResult:
    """Output of Protocol 4: the signing coalition C plus its audit trail."""

    #: True iff every disclosed share was attributed to a registered vehicle
    success: bool
    #: C -- registration indices of the traced vehicles, ascending
    indices: list = field(default_factory=list)
    #: ``"direct"``   : Protocol 4 lines 2-4, pk_j = (b_j * G - B_j) / gamma
    #: ``"fallback"`` : Corollary 2 subset test against Vp ({b_j} unavailable)
    method: str = "direct"
    #: threshold t recovered from the ciphertext (T0, T2)
    t_recovered: int = 0
    #: {pk_j} recovered on line 2, in the order in which the b_j were disclosed
    recovered_pks: list = field(default_factory=list)
    #: line 3 as a relation: (temporary index j, registration index i)
    matches: list = field(default_factory=list)
    #: temporary indices j whose pk_j has no counterpart in the list pk
    unmatched: list = field(default_factory=list)
    #: Corollary 2 binding sum_{i in C} pk_i + gamma^-1 sum B_j == Vp
    bound_to_Vp: bool = False
    #: fallback path only: candidate subsets really formed and really tested
    subsets_tested: int = 0
    #: C(n, t), the size of the fallback search space
    search_space: int = 0


class Tracer:
    """Holds skt = (pk1..pkn, skTr, pkR) and runs Protocol 4.

    Protocol 4 needs (sid, m, T0, T2, {B_j}) from the TMC and {b_j} from the
    RSU.  With those inputs the coalition is read off directly (line 2-4); the
    exhaustive subset test of Corollary 2 is only the fallback that applies
    when the individual b_j cannot be obtained.
    """

    def __init__(self, trace_key):
        self.pks, self.sk_Tr, self.pk_R = trace_key
        self.t = 0
        self.gamma = 0
        self.B = []          # {B_j} from the TMC
        self.b = []          # {(j, b_j)} from the RSU

    # -- Protocol 4, line 1 ----------------------------------------------- #
    def open_ciphertext(self, ct: SessionCiphertext):
        """t, gamma <- Decrypt(skTr, T0, T2): EC-ElGamal under skTr."""
        blob = crypto.ecelgamal_decrypt(self.sk_Tr, ct.T0, ct.T2)
        self.t, self.gamma = crypto.unpack_t_gamma(blob)
        return self.t, self.gamma

    def receive_masks(self, B):
        """{B_j} = {beta_j * G} from the TMC (alpha_j is never sent here)."""
        self.B = list(B)

    def receive_b(self, pairs):
        """{(j, b_j)} from the RSU."""
        self.b = list(pairs)

    # -- Protocol 4 ------------------------------------------------------- #
    def trace(self, sigma: AggregateSignature,
              force_fallback: bool = False) -> TraceResult:
        """Trace Signature.

        Input : skt, sigma = (R, sid, m, Vp, z)
        Output: C

            1: t, gamma <- Decrypt(skTr, T0, T2)
            2: pk_j     <- (b_j * G - B_j) / gamma
            3: match pk_j -> pk_i
            4: i -> C

        Line 1 is :meth:`open_ciphertext`; lines 2-4 are :meth:`trace_direct`.
        When the RSU cannot supply the individual b_j the Tracer falls back to
        the attribution rule of Corollary 2 (:meth:`trace_fallback`).
        """
        if self.b and not force_fallback:
            return self.trace_direct(sigma)
        return self.trace_fallback(sigma)

    def trace_direct(self, sigma: AggregateSignature) -> TraceResult:
        """Lines 2-4: recover pk_j from b_j, match it in pk, collect i into C.

        Corollary 2 gives the correctness of line 2 unconditionally:

            (b_j * G - B_j) * gamma^-1
                = (gamma*sk_j + beta_j - beta_j) * gamma^-1 * G
                = sk_j * G = pk_j,

        so no search over subsets is involved and the recovered set is the true
        signing coalition with probability 1.  The cost is t fixed-base scalar
        multiplications plus t lookups in the public key list, i.e. linear in t
        and n rather than combinatorial.
        """
        gamma_inv = curve.inv_mod_q(self.gamma)

        recovered, matches, unmatched, C = [], [], [], []
        for (j, b_j), B_j in zip(self.b, self.B):
            # line 2: pk_j <- (b_j * G - B_j) / gamma
            pk_j = curve.scalar_mul(gamma_inv, curve.point_sub(mul_G(b_j), B_j))
            recovered.append(pk_j)
            # line 3: search the public key list pk for the matching pk_i
            i = self.match(pk_j)
            if i < 0:
                unmatched.append(j)
                continue
            matches.append((j, i))
            C.append(i)                       # line 4: i -> C

        C = sorted(set(C))
        success = bool(C) and not unmatched and len(C) == len(self.b) == self.t
        return TraceResult(
            success=success,
            indices=C,
            method="direct",
            t_recovered=self.t,
            recovered_pks=recovered,
            matches=matches,
            unmatched=unmatched,
            bound_to_Vp=self.binds_to_Vp(C, sigma) if success else False,
            search_space=search_space(len(self.pks), self.t),
        )

    def match(self, pk_j) -> int:
        """Line 3: index of the entry of the public key list pk equal to pk_j."""
        for i, pk_i in enumerate(self.pks):
            if pk_i == pk_j:
                return i
        return -1

    def theta(self) -> tuple:
        """Theta = gamma^-1 * sum_{j in C} B_j   (Theorem 1)."""
        return curve.scalar_mul(curve.inv_mod_q(self.gamma), point_sum(self.B))

    def binds_to_Vp(self, indices, sigma: AggregateSignature) -> bool:
        """Corollary 2: bind the recovered C to the published aggregate,

            sum_{i in C} pk_i + gamma^-1 * sum_{j in C} B_j == Vp.
        """
        if not indices:
            return False
        return curve.point_add(point_sum(self.pks[i] for i in indices),
                              self.theta()) == sigma.Vp

    def trace_fallback(self, sigma: AggregateSignature) -> TraceResult:
        """Corollary 2 fallback, used when the individual b_j are unavailable.

        The identity above holds only for the true coalition, so the Tracer
        tests candidate subsets of size t against ``Q = Vp - Theta``.  The
        enumeration is strictly exhaustive: every one of the C(n, t) subsets is
        really formed and really tested (see :mod:`dtt_ecdsa.search`).
        """
        target = curve.point_sub(sigma.Vp, self.theta())
        indices, tested = exhaustive_subset_search(self.pks, target, self.t)
        return TraceResult(
            success=indices is not None,
            indices=indices or [],
            method="fallback",
            t_recovered=self.t,
            bound_to_Vp=indices is not None,
            subsets_tested=tested,
            search_space=search_space(len(self.pks), self.t),
        )


# --------------------------------------------------------------------------- #
# Public verification - any node of the VANET can run it
# --------------------------------------------------------------------------- #
def verify_signature(sigma: AggregateSignature) -> bool:
    """Corollary 1: u1 = c/z, u2 = rx/z, accept iff u1 * G + u2 * Vp == R.

    A single ordinary ECDSA verification under the session public key Vp; the
    verifier needs neither t, nor gamma, nor the masks, nor the membership of C.
    """
    if sigma.R is None or sigma.Vp is None:
        return False
    if not (1 <= sigma.z < Q):
        return False
    c = crypto.hash_to_scalar(sigma.sid, sigma.m_bytes)
    r_x = sigma.R[0] % Q
    z_inv = curve.inv_mod_q(sigma.z)
    u1 = c * z_inv % Q
    u2 = r_x * z_inv % Q
    return curve.point_add(mul_G(u1), curve.scalar_mul(u2, sigma.Vp)) == sigma.R


def verify_encapsulation(pk_R, sigma: AggregateSignature, sig) -> bool:
    """Outer IEEE 1609.2 layer: the RSU signature on sigma under skR (A5(iv))."""
    return crypto.ecdsa_verify(pk_R, sigma.to_bytes(), sig)


def random_plate(rng=None) -> str:
    letters = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    prov = "京沪渝苏浙粤鲁豫"
    pick = secrets.choice if rng is None else rng.choice
    return (pick(prov) + pick(letters)
            + "".join(pick("0123456789") for _ in range(3))
            + "".join(pick(letters) for _ in range(2)))
