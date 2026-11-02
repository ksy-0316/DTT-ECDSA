"""End-to-end orchestration of the four DTT-ECDSA phases.

    Phase 1  System initialization   (Protocol 1)  -- TA + Vehicles
    Phase 2  Generate signature      (Protocol 2)  -- TMC + Vehicles
    Phase 3  Combine signature       (Protocol 3)  -- RSU (+ TMC for Delta)
    Phase 4  Trace signature         (Protocol 4)  -- Tracer (+ RSU, TA)

Every phase returns a :class:`PhaseTiming` whose ``total_ms`` is the end-to-end
latency, i.e. the measured cryptographic time plus the analytically accumulated
inter-entity transmission delay (see :mod:`dtt_ecdsa.network`).
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from time import perf_counter

from . import crypto, curve, message as msgmod
from .curve import Q, mul_G
from .entities import (TA, TMC, RSU, Tracer, Vehicle, AggregateSignature,
                       SignatureShare, TraceResult, random_plate,
                       verify_encapsulation, verify_signature)
from .network import Channel


@dataclass
class PhaseTiming:
    """Latency of one phase: measured computation + accumulated link delay."""

    name: str
    compute_ms: float = 0.0
    channel: Channel = field(default_factory=Channel)

    @property
    def comm_ms(self) -> float:
        return self.channel.total_ms

    @property
    def total_ms(self) -> float:
        return self.compute_ms + self.comm_ms

    def __str__(self) -> str:
        return (f"{self.name}: {self.total_ms:.3f} ms "
                f"(compute {self.compute_ms:.3f} ms + comm {self.comm_ms:.3f} ms)")


class DTTECDSASession:
    """One complete message-reporting round with n registered vehicles.

    ``t`` of the n registered vehicles are drawn at random as the signing set C.
    Their registration indices are kept as ground truth so that the output of
    Protocol 4 can be checked, but no entity except the TMC ever sees the map
    ``temporary index j -> vehicle``.
    """

    def __init__(self, n: int, t: int, rng: random.Random | None = None,
                 session_counter: int = 1):
        if not (1 <= t <= n):
            raise ValueError(f"the constraint 1 <= t <= n is violated (n={n}, t={t})")
        self.n = n
        self.t = t
        self.rng = rng or random.Random()
        self.session_counter = session_counter

        self.ta: TA | None = None
        self.tmc: TMC | None = None
        self.rsu: RSU | None = None
        self.tracer: Tracer | None = None
        self.vehicles: list[Vehicle] = []

        self.sid = b""
        self.m = None
        self.m_bytes = b""
        self.signer_indices: list[int] = []   # ground truth, sorted
        self.shares: list[SignatureShare] = []
        self.sigma: AggregateSignature | None = None
        self.outer_sig = None
        self.ciphertext = None
        self.A: list = []
        self.B: list = []
        self.delta = 0
        self.consistency_ok = None
        self.trace_result: TraceResult | None = None

    # ------------------------------------------------------------------ #
    # Phase 1 -- System initialization (Protocol 1)
    # ------------------------------------------------------------------ #
    def initialize(self) -> PhaseTiming:
        timing = PhaseTiming("System initialization")
        ch = timing.channel

        t0 = perf_counter()
        ta = TA(security_param=128)
        ta.setup()                                   # curve, (skR, pkR), (skTr, pkTr)
        compute = perf_counter() - t0

        # the TA publishes the system parameters to every vehicle
        ch.send("TA", "Vehicle", "system parameters (G, q, pkR, pkTr)",
                TA.SYSPARAM_BYTES, self.n)

        # each vehicle picks ski, computes pki = ski * G and registers it
        t0 = perf_counter()
        for i in range(self.n):
            v = Vehicle(vid=f"VEH-{i + 1:03d}", plate=random_plate(self.rng))
            v.keygen()
            proof = self._prove_possession(v)        # assumption A5(i)
            if not ta.register(v, proof):
                raise RuntimeError(f"registration of {v.vid} failed")
            self.vehicles.append(v)
        compute += perf_counter() - t0

        # vid || plate || pki || proof of possession (W, u)
        ch.send("Vehicle", "TA", "registration (vid, pki, PoP)",
                Vehicle.REG_BYTES + curve.POINT_BYTES + curve.SCALAR_BYTES, self.n)

        # the TA assembles pk, skc, skt and hands them to RSU / Tracer / TMC
        t0 = perf_counter()
        self.rsu = RSU(ta.combine_key())
        self.tracer = Tracer(ta.trace_key())
        self.tmc = TMC(ta.pk_R, ta.pk_Tr, rng=self.rng)
        compute += perf_counter() - t0

        ch.send("TA", "RSU", "skc = (pk1..pkn, pkTr, skR)", ta.skc_bytes())
        ch.send("TA", "Tracer", "skt = (pk1..pkn, skTr, pkR)", ta.skt_bytes())
        ch.send("TA", "TMC", "pk = (pk1..pkn, pkTr, pkR)", ta.pk_bytes())

        self.ta = ta
        timing.compute_ms = compute * 1000.0
        return timing

    @staticmethod
    def _prove_possession(v: Vehicle):
        """Schnorr proof of possession of ski, verified by the TA (A5(i))."""
        w = curve.rand_scalar()
        W = mul_G(w)
        e = crypto.hash_to_scalar(curve.point_to_bytes(v.pk), curve.point_to_bytes(W))
        u = (w + e * v.sk) % Q
        return W, u

    # ------------------------------------------------------------------ #
    # Phase 2 -- Generate signature (Protocol 2)
    # ------------------------------------------------------------------ #
    def generate_signature(self, m: dict | None = None) -> PhaseTiming:
        timing = PhaseTiming("Signature generation")
        ch = timing.channel

        # -- the reported event m and the fresh session identifier sid ----
        self.m = m if m is not None else msgmod.generate_message(self.rng)
        self.m_bytes = msgmod.serialize(self.m)
        self.sid = msgmod.new_sid(self.session_counter)

        # the RSU announces the reporting round to all n registered vehicles,
        # so m does not have to be recounted inside the shares (Section VI-C)
        ch.send("RSU", "Vehicle", "round announcement (sid, H(m))",
                RSU.ANNOUNCE_BYTES, self.n)

        # -- TMC: dynamic threshold t, kappa, gamma and (T0, T1, T2) ------
        t0 = perf_counter()
        self.ciphertext = self.tmc.open_session(self.t)
        compute = perf_counter() - t0

        # -- the t signing vehicles are drawn at random among the n -------
        # (they are the vehicles that answered the announcement on demand)
        self.signer_indices = sorted(self.rng.sample(range(self.n), self.t))
        admitted = list(self.signer_indices)
        self.rng.shuffle(admitted)               # j is unrelated to the identity

        # -- TMC: alpha_j, beta_j, A_j = alpha_j*G, B_j = beta_j*G --------
        t0 = perf_counter()
        self.A, self.B = self.tmc.admit(admitted)
        compute += perf_counter() - t0

        self.rsu.receive_masks(self.A)
        self.tracer.receive_masks(self.B)

        ch.send("TMC", "RSU", "(T0, T1) and {A_j}",
                self.ciphertext.rsu_bytes() + self.t * curve.POINT_BYTES)
        ch.send("TMC", "Tracer", "(sid, m, T0, T2) and {B_j}",
                len(self.sid) + len(self.m_bytes)
                + self.ciphertext.tracer_bytes() + self.t * curve.POINT_BYTES)
        ch.send("TMC", "Vehicle", "(sid, m, j, gamma, alpha_j, beta_j)",
                TMC.PARAM_BYTES, self.t)

        # -- each admitted vehicle produces its share delta_j -------------
        t0 = perf_counter()
        shares = []
        for j, idx in enumerate(admitted, start=1):
            gamma, alpha_j, beta_j = self.tmc.params_for(j)
            shares.append(self.vehicles[idx].sign_share(
                self.sid, self.m, j, gamma, alpha_j, beta_j))
        compute += perf_counter() - t0
        self.shares = shares

        ch.send("Vehicle", "RSU", "share delta_j = (sid, j, R_j, a_j, b_j)",
                SignatureShare.WIRE_BYTES, self.t)

        timing.compute_ms = compute * 1000.0
        return timing

    # ------------------------------------------------------------------ #
    # Phase 3 -- Combine signature (Protocol 3)
    # ------------------------------------------------------------------ #
    def combine_signature(self) -> PhaseTiming:
        timing = PhaseTiming("Signature combination")
        ch = timing.channel

        t0 = perf_counter()
        self.rsu.open_ciphertext(self.ciphertext)           # recover (t, gamma)
        js = self.rsu.submitted_indices(self.shares)
        compute = perf_counter() - t0

        # the RSU reports which temporary indices actually submitted a share and
        # the TMC answers with Delta = -sum(alpha_j) over exactly that set
        ch.send("RSU", "TMC", "set {j} of submitted shares", max(1, self.t) * 4)
        t0 = perf_counter()
        self.delta = self.tmc.allocate_delta(js)
        compute += perf_counter() - t0
        ch.send("TMC", "RSU", "Delta", curve.SCALAR_BYTES)

        t0 = perf_counter()
        self.sigma, self.outer_sig, self.consistency_ok = self.rsu.combine(
            self.shares, self.m_bytes, self.delta)
        compute += perf_counter() - t0

        # the RSU broadcasts sigma inside an IEEE 1609.2 SignedData structure
        ch.send("RSU", "Network", "sigma = (R, sid, m, Vp, z) + sig",
                AggregateSignature.WIRE_BYTES)

        timing.compute_ms = compute * 1000.0
        return timing

    def verify(self) -> bool:
        """Public verifiability (Corollary 1): one plain ECDSA check under Vp."""
        return verify_signature(self.sigma)

    def verify_outer(self) -> bool:
        """Outer IEEE 1609.2 encapsulation signed by the RSU under skR."""
        return verify_encapsulation(self.ta.pk_R, self.sigma, self.outer_sig)

    # ------------------------------------------------------------------ #
    # Phase 4 -- Trace signature (Protocol 4)
    # ------------------------------------------------------------------ #
    def trace_signature(self, force_fallback: bool = False):
        """Run Protocol 4 on the challenged aggregate.

        The Tracer already holds (sid, m, T0, T2, {B_j}) from the TMC (phase 2);
        the RSU now discloses the challenged sigma together with the individual
        {b_j} that line 2 needs.  ``force_fallback=True`` withholds the {b_j} and
        exercises the Corollary 2 attribution rule instead, i.e. the strictly
        exhaustive test of the C(n, t) candidate subsets against Vp.
        """
        timing = PhaseTiming("Signature tracing")
        ch = timing.channel

        if force_fallback:
            pairs = []
            ch.send("RSU", "Tracer", "trace request (sigma)",
                    AggregateSignature.WIRE_BYTES)
        else:
            pairs = self.rsu.disclose_b(self.shares)
            ch.send("RSU", "Tracer", "trace request (sigma, {b_j})",
                    AggregateSignature.WIRE_BYTES + self.t * curve.SCALAR_BYTES)

        t0 = perf_counter()
        self.tracer.receive_b(pairs)
        self.tracer.open_ciphertext(self.ciphertext)     # line 1: (t, gamma)
        result: TraceResult = self.tracer.trace(
            self.sigma, force_fallback=force_fallback)   # lines 2-4
        compute = perf_counter() - t0
        self.trace_result = result

        # accountability chain: the TA maps the recovered keys to real identities
        ch.send("Tracer", "TA", "recovered key set C",
                max(len(result.indices), 1) * curve.POINT_BYTES)
        ch.send("TA", "Tracer", "identity mapping of C",
                max(len(result.indices), 1) * 24)

        timing.compute_ms = compute * 1000.0
        return timing, result

    # ------------------------------------------------------------------ #
    def ground_truth(self):
        return list(self.signer_indices)

    def signer_ids(self, indices=None):
        idx = self.signer_indices if indices is None else indices
        return [self.vehicles[i].vid for i in idx]


def run_round(n: int, t: int, rng: random.Random | None = None,
              session_counter: int = 1, force_fallback: bool = False):
    """Run the four phases once and return ``(session, timings, result)``.

    ``timings`` is a dict with the three latencies reported in Table V of the
    paper: initialisation, signature generation + combination, tracing.
    """
    session = DTTECDSASession(n, t, rng=rng, session_counter=session_counter)
    t_init = session.initialize()
    t_gen = session.generate_signature()
    t_cmb = session.combine_signature()
    ok_inner = session.verify()
    ok_outer = session.verify_outer()
    t_trc, result = session.trace_signature(force_fallback=force_fallback)

    timings = {
        "init": t_init,
        "generate": t_gen,
        "combine": t_cmb,
        "trace": t_trc,
        "sign_total_ms": t_gen.total_ms + t_cmb.total_ms,
        "verify_inner": ok_inner,
        "verify_outer": ok_outer,
    }
    return session, timings, result
