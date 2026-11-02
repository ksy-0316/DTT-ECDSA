"""Self-test of the DTT-ECDSA implementation (no user input required).

    python selftest.py

Checks the curve arithmetic, the EC-ElGamal encapsulation, the plain ECDSA
layer, the correctness and public verifiability of the aggregate signature, the
consistency test of Protocol 3, the four lines of Protocol 4 (direct recovery
pk_j = (b_j G - B_j)/gamma, the match against the public key list pk and the
binding of C to Vp), the strictness of the Corollary 2 exhaustive fallback and
the unforgeability of a tampered transcript.
"""

from __future__ import annotations

import random
import sys

from dtt_ecdsa import crypto, curve
from dtt_ecdsa.console import setup_console
from dtt_ecdsa.curve import Q, mul_G, point_sum
from dtt_ecdsa.entities import verify_signature
from dtt_ecdsa.message import generate_message, serialize
from dtt_ecdsa.scheme import DTTECDSASession
from dtt_ecdsa.search import exhaustive_subset_search, search_space

PASS, FAIL = 0, 0


def check(name: str, condition: bool, detail: str = ""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [ OK ] {name}" + (f"  ({detail})" if detail else ""))
    else:
        FAIL += 1
        print(f"  [FAIL] {name}" + (f"  ({detail})" if detail else ""))


def test_curve():
    print("\n-- secp256r1 arithmetic -------------------------------------")
    G = (curve.GX, curve.GY)
    check("generator on curve", curve.is_on_curve(G))
    check("order: q * G == infinity", curve.scalar_mul(Q, G) is None)
    k = curve.rand_scalar()
    check("comb table matches double-and-add", mul_G(k) == curve.scalar_mul(k, G))
    a, b = curve.rand_scalar(), curve.rand_scalar()
    check("homomorphism (a+b)G == aG + bG",
          mul_G((a + b) % Q) == curve.point_add(mul_G(a), mul_G(b)))
    check("P - P == infinity", curve.point_sub(mul_G(a), mul_G(a)) is None)
    check("point_sum of many points",
          point_sum([mul_G(a), mul_G(b)]) == mul_G((a + b) % Q))


def test_crypto():
    print("\n-- EC-ElGamal and ECDSA -------------------------------------")
    sk = curve.rand_scalar()
    pk = mul_G(sk)
    kappa = curve.rand_scalar()
    gamma = curve.rand_scalar()
    blob = crypto.pack_t_gamma(7, gamma)
    T0 = mul_G(kappa)
    c2 = crypto.ecelgamal_encrypt(pk, kappa, blob)
    back = crypto.unpack_t_gamma(crypto.ecelgamal_decrypt(sk, T0, c2))
    check("EC-ElGamal decrypt(encrypt(t, gamma)) == (t, gamma)",
          back == (7, gamma))
    wrong = crypto.ecelgamal_decrypt(curve.rand_scalar(), T0, c2)
    check("EC-ElGamal is not decryptable with a foreign key", wrong != blob)

    msg = serialize(generate_message(random.Random(1)))
    sig = crypto.ecdsa_sign(sk, msg)
    check("ECDSA verifies a genuine signature", crypto.ecdsa_verify(pk, msg, sig))
    check("ECDSA rejects a modified message",
          not crypto.ecdsa_verify(pk, msg + b"!", sig))
    check("ECDSA rejects a foreign public key",
          not crypto.ecdsa_verify(mul_G(curve.rand_scalar()), msg, sig))


def test_search():
    print("\n-- Corollary 2 fallback: strict exhaustive search ------------")
    rng = random.Random(7)
    n, t = 9, 4
    sks = [curve.rand_scalar() for _ in range(n)]
    pks = [mul_G(s) for s in sks]
    truth = sorted(rng.sample(range(n), t))
    target = point_sum(pks[i] for i in truth)
    found, tested = exhaustive_subset_search(pks, target, t)
    check("the planted subset is recovered", found == truth,
          f"C({n},{t})={search_space(n, t)}, tested {tested}")
    bogus = mul_G(curve.rand_scalar())
    found, tested = exhaustive_subset_search(pks, bogus, t)
    check("an unreachable target exhausts the whole space",
          found is None and tested == search_space(n, t),
          f"tested {tested} / {search_space(n, t)}")
    # t > n/2 exercises the complement walk
    t2 = 7
    truth2 = sorted(rng.sample(range(n), t2))
    target2 = point_sum(pks[i] for i in truth2)
    found2, _ = exhaustive_subset_search(pks, target2, t2)
    check("complement walk returns the same subset (t > n/2)", found2 == truth2)


def test_protocol():
    print("\n-- four-phase protocol --------------------------------------")
    rng = random.Random(2026)
    n, t = 12, 5
    s = DTTECDSASession(n, t, rng=rng)
    s.initialize()
    check(f"{n} vehicles registered and indexed", len(s.ta.registry) == n)
    check("registered public keys are distinct",
          len({v.pk for v in s.vehicles}) == n)

    s.generate_signature()
    for field in ("Message Type", "Message ID", "Timestamp",
                  "Location", "Event Details"):
        check(f"message carries '{field}'", field in s.m)
    check(f"{t} signing vehicles drawn at random",
          len(s.signer_indices) == t and len(set(s.signer_indices)) == t)
    check("shares are indexed j = 1..t",
          sorted(sh.j for sh in s.shares) == list(range(1, t + 1)))
    check("A_j = alpha_j G and B_j = beta_j G are published separately",
          [mul_G(s.tmc.alphas[j]) for j in range(1, t + 1)] == s.A
          and [mul_G(s.tmc.betas[j]) for j in range(1, t + 1)] == s.B)

    s.combine_signature()
    check("Protocol 3 consistency test sum(a_j)G == gamma R + A",
          s.consistency_ok is True)
    check("RSU decrypted (t, gamma) correctly",
          s.rsu.t == t and s.rsu.gamma == s.tmc.gamma)
    check("sum(alpha_j) + Delta == 0",
          (sum(s.tmc.alphas.values()) + s.delta) % Q == 0)
    check("public verification of sigma (Corollary 1)", s.verify())
    check("outer IEEE 1609.2 signature of the RSU", s.verify_outer())

    tampered = s.sigma
    saved = tampered.m_bytes
    tampered.m_bytes = saved + b" "
    check("a tampered message breaks verification", not verify_signature(tampered))
    tampered.m_bytes = saved

    _, result = s.trace_signature()
    check("Protocol 4 runs the direct recovery of line 2",
          result.method == "direct")
    check("tracing recovers exactly the signing coalition",
          result.success and sorted(result.indices) == s.ground_truth(),
          f"{sorted(result.indices)}")
    check("Tracer decrypted (t, gamma) correctly",
          s.tracer.t == t and s.tracer.gamma == s.tmc.gamma)
    check("line 2: every pk_j = (b_j G - B_j)/gamma is the signer's pk",
          all(pk_j == s.vehicles[s.tmc.admitted[sh.j - 1]].pk
              for pk_j, sh in zip(result.recovered_pks, s.shares)))
    check("line 3: every pk_j found its match pk_i in the list pk",
          result.unmatched == [] and len(result.matches) == t)
    check("line 4: the matched indices are the real signers",
          all(s.tmc.admitted[j - 1] == i for j, i in result.matches))
    check("recovered C is bound to Vp (Corollary 2)", result.bound_to_Vp)
    check("Vp equals sum(pk_i) + gamma^-1 sum(B_j)",
          curve.point_add(
              point_sum(s.vehicles[i].pk for i in s.ground_truth()),
              curve.scalar_mul(curve.inv_mod_q(s.tmc.gamma), point_sum(s.B)),
          ) == s.sigma.Vp)
    check("TMC audit of every share succeeds",
          all(s.tmc.audit_share(sh, s.vehicles[idx].pk, s.B[sh.j - 1])
              for sh, idx in zip(s.shares, s.tmc.admitted)))

    # the Corollary 2 fallback must agree with the direct recovery
    _, fb = s.trace_signature(force_fallback=True)
    check("Corollary 2 fallback returns the same coalition",
          fb.method == "fallback" and fb.success
          and sorted(fb.indices) == s.ground_truth(),
          f"tested {fb.subsets_tested} / {fb.search_space}")


def test_trace_forgery():
    print("\n-- Protocol 4 rejects a forged b_j --------------------------")
    n, t = 8, 3
    s = DTTECDSASession(n, t, rng=random.Random(99))
    s.initialize()
    s.generate_signature()
    s.combine_signature()

    pairs = s.rsu.disclose_b(s.shares)
    j0, b0 = pairs[0]
    s.tracer.open_ciphertext(s.ciphertext)
    s.tracer.receive_b([(j0, (b0 + 1) % Q)] + pairs[1:])
    res = s.tracer.trace(s.sigma)
    check("a modified b_j leaves pk_j unmatched",
          not res.success and res.unmatched == [j0], str(res.unmatched))
    check("the remaining shares are still attributed correctly",
          [i for _, i in res.matches]
          == [s.tmc.admitted[j - 1] for j, _ in pairs[1:]])

    # without {b_j} the Tracer falls back to the exhaustive rule of Corollary 2
    s.tracer.receive_b([])
    res = s.tracer.trace(s.sigma)
    check("an empty {b_j} selects the fallback automatically",
          res.method == "fallback" and res.success
          and sorted(res.indices) == s.ground_truth())


def test_edges():
    print("\n-- boundary cases -------------------------------------------")
    for n, t in ((1, 1), (2, 1), (5, 5), (6, 3)):
        s = DTTECDSASession(n, t, rng=random.Random(n * 31 + t))
        s.initialize()
        s.generate_signature()
        s.combine_signature()
        _, res = s.trace_signature()
        ok = s.verify() and res.success and sorted(res.indices) == s.ground_truth()
        check(f"(n, t) = ({n}, {t})", ok)


def main() -> int:
    setup_console()
    print("=" * 62)
    print("  DTT-ECDSA self-test")
    print("=" * 62)
    test_curve()
    test_crypto()
    test_search()
    test_protocol()
    test_trace_forgery()
    test_edges()
    print("\n" + "=" * 62)
    print(f"  {PASS} passed, {FAIL} failed")
    print("=" * 62)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
