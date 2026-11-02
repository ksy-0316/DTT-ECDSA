"""DTT-ECDSA: a dynamic traceable threshold ECDSA scheme for VANETs.

Reference implementation of

    "DTT-ECDSA: Dynamic Traceable Threshold ECDSA for Secure Message Reporting
     in Vehicular Ad Hoc Networks"

over the NIST curve **secp256r1**, with the five entities of the framework
(TA, RSU, TMC, Tracer, Vehicle) and the four protocols:

    Protocol 1  System initialization
    Protocol 2  Generate signature
    Protocol 3  Combine signature
    Protocol 4  Trace signature      (pk_j = (b_j*G - B_j)/gamma, match in pk)

Protocol 4 reads the signing coalition off directly, one disclosed share at a
time; the strictly exhaustive test of all C(n, t) candidate subsets against Vp
is the fallback attribution rule of Corollary 2, used when the individual b_j
are unavailable.

The implementation depends on nothing outside the Python standard library.
"""

from . import console, crypto, curve, message, network, search
from .curve import CURVE_NAME
from .entities import (TA, TMC, RSU, Tracer, Vehicle, AggregateSignature,
                       SessionCiphertext, SignatureShare, TraceResult,
                       random_plate, verify_encapsulation, verify_signature)
from .message import format_message, generate_message, new_sid, serialize
from .network import BANDWIDTH_MBPS, LINK_LATENCY_MS, Channel, tx_ms
from .scheme import DTTECDSASession, PhaseTiming, run_round
from .search import exhaustive_subset_search, search_space

__version__ = "2.0.0"

__all__ = [
    "CURVE_NAME",
    "TA", "TMC", "RSU", "Tracer", "Vehicle",
    "AggregateSignature", "SessionCiphertext", "SignatureShare", "TraceResult",
    "verify_signature", "verify_encapsulation", "random_plate",
    "DTTECDSASession", "PhaseTiming", "run_round",
    "exhaustive_subset_search", "search_space",
    "generate_message", "serialize", "new_sid", "format_message",
    "Channel", "tx_ms", "LINK_LATENCY_MS", "BANDWIDTH_MBPS",
    "console", "crypto", "curve", "message", "network", "search",
]
