"""DTT-ECDSA benchmark runner.

For a fixed threshold ``t`` the runner sweeps the group sizes

    n in { n : ceil(1.5 t) <= n <= 30 and n mod 3 == 0 }

and executes ``x`` independent rounds per group.  Every round measures three
latencies, each of which already contains the inter-entity communication delay
of the analytic link model (2 ms single-hop latency, 6 Mbps effective
bandwidth, see :mod:`dtt_ecdsa.network`):

    1. 初始化              Protocol 1
    2. 签名生成 + 签名聚合  Protocol 2 + Protocol 3
    3. 追踪                Protocol 4

The tracing latency is that of Protocol 4 as specified, i.e. the direct
recovery ``pk_j = (b_j * G - B_j) / gamma`` followed by the lookup of each
``pk_j`` in the public key list ``pk``.  Setting :data:`MEASURE_FALLBACK` adds
one further column with the latency of the Corollary 2 fallback rule (the
strictly exhaustive test of all C(n, t) candidate subsets against Vp), which
only applies when the individual ``b_j`` are unavailable.

All values are reported in milliseconds with three decimals.  The per-round
traced vehicle set and the x-round averages of each group are written to
``result/t=<t>.txt``.

    python runner.py
"""

from __future__ import annotations

import os
import random
import sys
import time
from math import ceil

from dtt_ecdsa import curve
from dtt_ecdsa.console import pad, setup_console
from dtt_ecdsa.network import BANDWIDTH_MBPS, LINK_LATENCY_MS
from dtt_ecdsa.scheme import DTTECDSASession
from dtt_ecdsa.search import search_space

RESULT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "result")
N_MAX = 30
N_STEP = 3
LINE = "=" * 78
THIN = "-" * 78

#: 额外测量推论 2 的穷举回退规则（多出一列）。协议 4 本身不需要穷举，
#: 打开后单轮耗时由 C(n,t) 决定，可能从毫秒级变成分钟级。
MEASURE_FALLBACK = False
#: 开启回退测量时，搜索空间超过该值的分组不再测量回退（只留空）
FALLBACK_LIMIT = 50_000_000


# --------------------------------------------------------------------------- #
def group_sizes(t: int):
    """Multiples of 3 in the interval [ceil(1.5 t), 30]."""
    low = ceil(1.5 * t)
    start = low + (-low) % N_STEP              # round up to a multiple of 3
    return [n for n in range(start, N_MAX + 1, N_STEP) if n >= t]


def ask_int(prompt: str, low: int, high: int | None = None) -> int:
    while True:
        try:
            raw = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)
        if not raw:
            continue
        try:
            value = int(raw)
        except ValueError:
            print("  [!] 请输入一个整数。")
            continue
        if value < low or (high is not None and value > high):
            hi = "" if high is None else f" 且不超过 {high}"
            print(f"  [!] 取值必须不小于 {low}{hi}。")
            continue
        return value


def run_once(n: int, t: int, rng: random.Random, counter: int) -> dict:
    """One round of the four phases; all times in ms."""
    session = DTTECDSASession(n, t, rng=rng, session_counter=counter)

    t_init = session.initialize()
    t_gen = session.generate_signature()
    t_cmb = session.combine_signature()

    # correctness checks are deliberately performed outside the timing window:
    # they belong to the verifier, not to the signature-generation phase
    ok_sig = bool(session.verify() and session.verify_outer()
                  and session.consistency_ok)

    # Protocol 4: pk_j = (b_j*G - B_j)/gamma, then match pk_j -> pk_i -> C
    t_trc, result = session.trace_signature()

    traced = sorted(result.indices)
    row = {
        "init_ms": t_init.total_ms,
        "sign_ms": t_gen.total_ms + t_cmb.total_ms,
        "trace_ms": t_trc.total_ms,
        "traced_ids": [session.vehicles[i].vid for i in traced],
        "truth_ids": session.signer_ids(),
        "ok_sig": ok_sig,
        "ok_trace": result.success and traced == session.ground_truth(),
        "bound": result.bound_to_Vp,
        "unmatched": list(result.unmatched),
        "fallback_ms": None,
        "fallback_ok": None,
    }

    if MEASURE_FALLBACK and result.search_space <= FALLBACK_LIMIT:
        fb_timing, fb = session.trace_signature(force_fallback=True)
        row["fallback_ms"] = fb_timing.total_ms
        row["fallback_ok"] = fb.success and sorted(fb.indices) == traced
    return row


# --------------------------------------------------------------------------- #
def main() -> int:
    setup_console()
    print(LINE)
    print("  DTT-ECDSA 性能测试 (runner)")
    print(f"  椭圆曲线: {curve.CURVE_NAME} (NIST P-256)")
    print(f"  通信模型: 单跳时延 {LINK_LATENCY_MS:g} ms, 有效带宽 "
          f"{BANDWIDTH_MBPS:g} Mbps")
    print(f"  追踪方式: 协议 4  pk_j = (b_j*G - B_j)/gamma, 再在 pk 中匹配 pk_i")
    if MEASURE_FALLBACK:
        print(f"  另测回退: 推论 2 的严格穷举规则 (C(n,t) 个候选集合)")
    print(LINE)

    # ---------------- 两个用户输入 ---------------- #
    t = ask_int("  请输入门限值 t: ", 1, N_MAX)
    x = ask_int("  请输入每组测试轮数 x: ", 1)

    groups = group_sizes(t)
    if not groups:
        print(f"  [!] t = {t} 时 [1.5t, {N_MAX}] 内没有 3 的倍数，无可测试的分组。")
        return 1

    print()
    print(f"  门限 t = {t}, 每组运行 {x} 轮")
    print(f"  测试分组 n = {', '.join(str(n) for n in groups)}")
    if MEASURE_FALLBACK:
        print(f"  各组回退搜索空间 C(n,t): "
              + ", ".join(f"C({n},{t})={search_space(n, t)}" for n in groups))
    print()

    os.makedirs(RESULT_DIR, exist_ok=True)
    out_path = os.path.join(RESULT_DIR, f"t={t}.txt")
    rng = random.Random()
    counter = 0
    started = time.strftime("%Y-%m-%d %H:%M:%S")

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(LINE + "\n")
        fh.write("DTT-ECDSA 性能测试结果\n")
        fh.write(LINE + "\n")
        fh.write(f"椭圆曲线        : {curve.CURVE_NAME} (NIST P-256)\n")
        fh.write(f"门限值 t        : {t}\n")
        fh.write(f"每组测试轮数 x  : {x}\n")
        fh.write(f"测试分组 n      : {', '.join(str(n) for n in groups)}\n")
        fh.write(f"通信模型        : 单跳时延 {LINK_LATENCY_MS:g} ms, "
                 f"有效带宽 {BANDWIDTH_MBPS:g} Mbps "
                 f"(时间 = 计算时间 + 主体间交互时间)\n")
        fh.write(f"时间单位        : ms (保留 3 位小数)\n")
        fh.write(f"追踪方式        : 协议 4 -- 对每个 b_j 计算 "
                 f"pk_j = (b_j*G - B_j)/gamma, 再在公钥列表 pk 中\n")
        fh.write(f"                  检索与之相等的 pk_i, 将 i 收入签名车辆集合 C\n")
        if MEASURE_FALLBACK:
            fh.write(f"回退规则        : 推论 2 -- 无法获得单个 b_j 时, 严格穷举"
                     f"全部 C(n,t) 个候选集合\n")
        fh.write(f"开始时间        : {started}\n")
        fh.write(LINE + "\n\n")
        fh.flush()

        summary = []
        for n in groups:
            head = f"分组: n = {n}, t = {t}"
            if MEASURE_FALLBACK:
                head += f"  (回退穷举空间 C({n},{t}) = {search_space(n, t)})"
            print(THIN)
            print(f"  {head}")
            print(THIN)
            fh.write(THIN + "\n" + head + "\n" + THIN + "\n")
            header = (pad("轮次", 6) + pad("初始化(ms)", 14, ">")
                      + pad("签名生成+聚合(ms)", 22, ">")
                      + pad("追踪(ms)", 14, ">"))
            if MEASURE_FALLBACK:
                header += pad("回退穷举(ms)", 18, ">")
            fh.write(header + "   追踪车辆集合\n")

            acc = [0.0, 0.0, 0.0]
            acc_fb, n_fb = 0.0, 0
            all_ok = True
            for r in range(1, x + 1):
                counter += 1
                row = run_once(n, t, rng, counter)
                acc[0] += row["init_ms"]
                acc[1] += row["sign_ms"]
                acc[2] += row["trace_ms"]
                ok = row["ok_trace"]
                all_ok = all_ok and ok and row["ok_sig"]

                ids = "{" + ", ".join(row["traced_ids"]) + "}"
                line = (f"{r:<6d}{row['init_ms']:>14.3f}"
                        f"{row['sign_ms']:>22.3f}{row['trace_ms']:>14.3f}")
                if MEASURE_FALLBACK:
                    if row["fallback_ms"] is None:
                        line += pad("-", 18, ">")
                    else:
                        line += f"{row['fallback_ms']:>18.3f}"
                        acc_fb += row["fallback_ms"]
                        n_fb += 1
                fh.write(line + f"   {ids}\n")
                if not ok:
                    fh.write(f"{'':6s}[!] 追踪结果与真实签名集合不一致: "
                             f"真实 = {{{', '.join(row['truth_ids'])}}}")
                    if row["unmatched"]:
                        fh.write(f", 未匹配的临时编号 j = "
                                 f"{row['unmatched']}")
                    fh.write("\n")
                if not row["ok_sig"]:
                    fh.write(f"{'':6s}[!] 签名验证未通过\n")
                if not row["bound"]:
                    fh.write(f"{'':6s}[!] 推论 2 的绑定关系 "
                             f"sum(pk_i)+gamma^-1*sum(B_j) == Vp 不成立\n")
                if row["fallback_ok"] is False:
                    fh.write(f"{'':6s}[!] 回退穷举结果与直接还原结果不一致\n")
                fh.flush()

                extra = "" if row["fallback_ms"] is None else \
                    f" | 回退 {row['fallback_ms']:11.3f} ms"
                print(f"    第 {r:>3d}/{x} 轮  初始化 {row['init_ms']:9.3f} ms | "
                      f"签名 {row['sign_ms']:9.3f} ms | "
                      f"追踪 {row['trace_ms']:9.3f} ms{extra} | "
                      f"{'OK' if ok else 'FAIL'}")

            avg = [v / x for v in acc]
            avg_fb = acc_fb / n_fb if n_fb else None
            tail = (pad("平均", 6) + f"{avg[0]:>14.3f}{avg[1]:>22.3f}"
                    f"{avg[2]:>14.3f}")
            if MEASURE_FALLBACK:
                tail += pad("-", 18, ">") if avg_fb is None else f"{avg_fb:>18.3f}"
            fh.write(tail + f"   ({x} 轮平均)\n")
            fh.write(f"追踪正确率: {'100% (全部正确)' if all_ok else '存在失败轮次'}\n\n")
            fh.flush()

            summary.append((n, avg[0], avg[1], avg[2], avg_fb, all_ok))
            print(f"    -> {x} 轮平均: 初始化 {avg[0]:.3f} ms | "
                  f"签名生成+聚合 {avg[1]:.3f} ms | 追踪 {avg[2]:.3f} ms"
                  + ("" if avg_fb is None else f" | 回退穷举 {avg_fb:.3f} ms"))
            print()

        # ---------------- 汇总 ---------------- #
        fh.write(LINE + "\n")
        fh.write(f"汇总: t = {t}, 每组 {x} 轮平均时间 (ms)\n")
        fh.write(LINE + "\n")
        head = (pad("n", 6) + pad("初始化", 14, ">") + pad("签名生成+聚合", 20, ">")
                + pad("追踪", 16, ">") + pad("总计", 14, ">"))
        if MEASURE_FALLBACK:
            head += pad("回退穷举", 18, ">")
        fh.write(head + "   追踪\n")
        for n, a0, a1, a2, afb, ok in summary:
            row = (f"{n:<6d}{a0:>14.3f}{a1:>20.3f}{a2:>16.3f}"
                   f"{a0 + a1 + a2:>14.3f}")
            if MEASURE_FALLBACK:
                row += pad("-", 18, ">") if afb is None else f"{afb:>18.3f}"
            fh.write(row + f"   {'正确' if ok else '失败'}\n")
        fh.write(LINE + "\n")
        fh.write(f"结束时间        : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    print(LINE)
    print(f"  汇总 (t = {t}, 每组 {x} 轮平均, 单位 ms)")
    print(LINE)
    head = ("  " + pad("n", 6) + pad("初始化", 12, ">")
            + pad("签名生成+聚合", 18, ">") + pad("追踪", 14, ">")
            + pad("总计", 12, ">"))
    if MEASURE_FALLBACK:
        head += pad("回退穷举", 16, ">")
    print(head)
    for n, a0, a1, a2, afb, ok in summary:
        row = f"  {n:<6d}{a0:>12.3f}{a1:>18.3f}{a2:>14.3f}{a0 + a1 + a2:>12.3f}"
        if MEASURE_FALLBACK:
            row += pad("-", 16, ">") if afb is None else f"{afb:>16.3f}"
        print(row)
    print(LINE)
    print(f"  结果已保存到: {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())