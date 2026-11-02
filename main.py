"""DTT-ECDSA demonstration program.

Runs one complete message-reporting round over secp256r1:

    n vehicles register with the TA, t of them are drawn at random as the
    signing coalition, the RSU aggregates their shares into a single signature
    and the Tracer recovers the coalition with Protocol 4, i.e. by computing
    pk_j = (b_j * G - B_j) / gamma for every disclosed share and matching each
    pk_j against the public key list pk.

For completeness the program also exercises the fallback attribution rule of
Corollary 2 -- the strictly exhaustive test of all C(n, t) candidate subsets
against Vp -- whenever the search space stays below ``FALLBACK_DEMO_LIMIT``.

The program asks exactly two questions: the number of vehicles n and the
threshold t.

    python main.py
"""

from __future__ import annotations

import random
import sys

from dtt_ecdsa import curve, message as msgmod
from dtt_ecdsa.console import pad, setup_console
from dtt_ecdsa.scheme import DTTECDSASession
from dtt_ecdsa.search import search_space

LINE = "=" * 74
THIN = "-" * 74

#: above this search space the Corollary 2 fallback is only described, not run
FALLBACK_DEMO_LIMIT = 2_000_000


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


def banner():
    print(LINE)
    print("  DTT-ECDSA  动态可追踪门限 ECDSA 车联网消息上报方案")
    print(f"  椭圆曲线: {curve.CURVE_NAME} (NIST P-256)")
    print("  实体: TA / RSU / TMC / Tracer / 车辆")
    print(LINE)


def main() -> int:
    setup_console()
    banner()

    # ---------------- 两个用户输入 ---------------- #
    n = ask_int("  请输入注册车辆数 n: ", 1)
    t = ask_int(f"  请输入门限值 t (1 <= t <= {n}): ", 1, n)
    print()

    rng = random.Random()
    session = DTTECDSASession(n, t, rng=rng, session_counter=1)

    # ---------------- 阶段 1: 系统初始化 ---------------- #
    print(THIN)
    print("  阶段 1 / 4  系统初始化 (Protocol 1: System Initialization)")
    print(THIN)
    timing = session.initialize()
    print(f"    TA 完成系统参数生成, 曲线 = {curve.CURVE_NAME}")
    print(f"    TA 为 RSU 生成密钥对 (skR, pkR), 为 Tracer 生成密钥对 (skTr, pkTr)")
    print(f"    {n} 辆车完成注册 (已验证私钥持有证明), 车辆 ID 保留如下:")
    ids = [v.vid for v in session.vehicles]
    for k in range(0, len(ids), 8):
        print("      " + "  ".join(pad(v, 9) for v in ids[k:k + 8]))
    print(f"    TA 分发: skc -> RSU, skt -> Tracer, pk -> TMC")
    print(f"    用时: {timing.total_ms:.3f} ms  "
          f"(计算 {timing.compute_ms:.3f} ms + 通信 {timing.comm_ms:.3f} ms)")
    print("  >> 系统初始化阶段已完成\n")

    # ---------------- 阶段 2: 签名生成 ---------------- #
    print(THIN)
    print("  阶段 2 / 4  签名生成 (Protocol 2: Generate Signature)")
    print(THIN)
    timing = session.generate_signature()
    print(f"    随机生成的上报消息 m ({len(session.m_bytes)} 字节):")
    print(msgmod.format_message(session.m, indent=6))
    print(f"    会话标识 sid = {session.sid.hex()}")
    print(f"    TMC 选定动态门限 t = {t}, 并用 EC-ElGamal 加密 (t || gamma):")
    print(f"      T0 = kappa*G, T1 -> RSU (skR 解密), T2 -> Tracer (skTr 解密)")
    print(f"    TMC 随机选出 {t} 辆签名车辆并分配临时编号 j = 1..{t}")
    print(f"      本轮签名车辆 (真实身份, 仅 TMC 可见): "
          f"{', '.join(session.signer_ids())}")
    print(f"    TMC 下发 (gamma, alpha_j, beta_j), 并公布 A_j=alpha_j*G -> RSU, "
          f"B_j=beta_j*G -> Tracer")
    print(f"    {t} 辆车各自生成签名份额 delta_j = (sid, m, j, R_j, a_j, b_j)")
    print(f"    用时: {timing.total_ms:.3f} ms  "
          f"(计算 {timing.compute_ms:.3f} ms + 通信 {timing.comm_ms:.3f} ms)")
    print("  >> 签名生成阶段已完成\n")

    # ---------------- 阶段 3: 签名聚合 ---------------- #
    print(THIN)
    print("  阶段 3 / 4  签名聚合 (Protocol 3: Combine Signature)")
    print(THIN)
    timing = session.combine_signature()
    sigma = session.sigma
    ok_inner = session.verify()
    ok_outer = session.verify_outer()
    print(f"    RSU 用 skR 解密 T1, 恢复出 (t, gamma) = ({session.rsu.t}, "
          f"0x{session.rsu.gamma:064x})"[:110])
    print(f"    TMC 依据实际提交份额的编号集合下发 Delta, 满足 sum(alpha_j)+Delta=0")
    print(f"    一致性检验 sum(a_j)*G == gamma*R + A : "
          f"{'通过' if session.consistency_ok else '未通过'}")
    print(f"    聚合结果 sigma = (R, sid, m, Vp, z):")
    print(f"      R.x = 0x{sigma.R[0]:064x}")
    print(f"      Vp.x= 0x{sigma.Vp[0]:064x}")
    print(f"      z   = 0x{sigma.z:064x}")
    print(f"    公开验证 (推论 1, 任何车辆均可执行): "
          f"{'通过' if ok_inner else '未通过'}")
    print(f"    RSU 对 sigma 的外层 IEEE 1609.2 签名验证: "
          f"{'通过' if ok_outer else '未通过'}")
    print(f"    用时: {timing.total_ms:.3f} ms  "
          f"(计算 {timing.compute_ms:.3f} ms + 通信 {timing.comm_ms:.3f} ms)")
    print("  >> 签名聚合阶段已完成\n")

    # ---------------- 阶段 4: 追踪 ---------------- #
    print(THIN)
    print("  阶段 4 / 4  签名追踪 (Protocol 4: Trace Signature)")
    print(THIN)
    space = search_space(n, t)
    print(f"    Tracer 用 skTr 解密 (T0, T2) 得到 (t, gamma)          -- 第 1 行")
    print(f"    对每个已披露的 b_j 计算 pk_j = (b_j*G - B_j) / gamma  -- 第 2 行")
    print(f"    在公钥列表 pk 中检索与 pk_j 相等的 pk_i               -- 第 3 行")
    print(f"    将命中的注册序号 i 收入签名车辆集合 C                 -- 第 4 行")
    timing, result = session.trace_signature()

    truth = session.ground_truth()
    traced = sorted(result.indices)
    traced_ids = [session.vehicles[i].vid for i in traced]
    correct = result.success and traced == truth

    print()
    print("    ---------------- 追踪结果 ----------------")
    if result.success:
        print(f"    追踪成功: {len(result.matches)} 个份额全部在公钥列表 pk 中找到对应车辆")
        print(f"    追踪出的签名车辆集合 C (共 {len(traced)} 辆):")
        ident = {i: info for i, info in
                 zip(traced, session.ta.identify(traced))}
        for k, (j, i) in enumerate(sorted(result.matches, key=lambda p: p[0]), 1):
            info = ident[i]
            print(f"      {k:>3d}. 临时编号 j = {j:<3d} -> pk_{i + 1:<3d}  "
                  f"车辆 ID = {pad(info[1], 9)}  注册序号 = {i + 1:>3d}  "
                  f"车牌 = {info[2]}")
        print(f"    追踪集合 C   = {{{', '.join(traced_ids)}}}")
        print(f"    实际签名集合 = {{{', '.join(session.signer_ids())}}}")
        print(f"    追踪正确性: {'完全一致 (追踪正确)' if correct else '不一致 (追踪错误)'}")
        print(f"    与聚合签名的绑定 sum_{{i in C}} pk_i + gamma^-1*sum(B_j) == Vp: "
              f"{'成立' if result.bound_to_Vp else '不成立'}  (推论 2)")
    else:
        print(f"    追踪失败: 有 {len(result.unmatched)} 个份额 (j = "
              f"{', '.join(str(j) for j in result.unmatched)}) 未能在公钥列表中匹配")
    print(f"    用时: {timing.total_ms:.3f} ms  "
          f"(计算 {timing.compute_ms:.3f} ms + 通信 {timing.comm_ms:.3f} ms)")

    # -- 推论 2 的回退规则: 无法获得单个 b_j 时, 严格穷举全部 C(n,t) 个子集 -- #
    print()
    print(f"    回退规则 (推论 2, 仅当无法获得单个 b_j 时使用):")
    print(f"      Theta = gamma^-1 * sum(B_j),  目标点 Q = Vp - Theta")
    print(f"      严格穷举全部 C({n},{t}) = {space} 个候选集合, 检验 "
          f"sum_{{i in C}} pk_i == Q")
    if space <= FALLBACK_DEMO_LIMIT:
        fb_timing, fb = session.trace_signature(force_fallback=True)
        fb_ids = [session.vehicles[i].vid for i in sorted(fb.indices)]
        print(f"      回退追踪结果: "
              + (f"{{{', '.join(fb_ids)}}}" if fb.success else "未找到匹配"))
        print(f"      与第 2 行的直接还原结果: "
              f"{'一致' if sorted(fb.indices) == traced else '不一致'}")
        print(f"      实际检验 {fb.subsets_tested} / {space} 个候选集合")
        print(f"      用时: {fb_timing.total_ms:.3f} ms  "
              f"(计算 {fb_timing.compute_ms:.3f} ms + 通信 "
              f"{fb_timing.comm_ms:.3f} ms)")
    else:
        print(f"      C({n},{t}) = {space} 超过演示上限 {FALLBACK_DEMO_LIMIT}, 本次跳过")
    print("  >> 签名追踪阶段已完成\n")

    print(LINE)
    print("  四个阶段全部执行完毕。")
    print(LINE)
    return 0 if correct else 1


if __name__ == "__main__":
    sys.exit(main())
