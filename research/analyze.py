"""Statistical analysis of the defense sweep.

Consumes the long-format CSV from :mod:`research.extract_metrics` (one row per
episode x defender config) and produces the study's headline results:

* ``summary_by_cell.csv`` - per defender cell: detection rate, false-positive
  rate, mean time-to-detect, prevention, each with a bootstrap 95% CI.
* ``operating_curve.png`` - the detection-effectiveness vs false-positive
  tradeoff, one series per containment scope.
* ``km_time_to_contain.png`` - Kaplan-Meier time-to-containment by scope, with a
  log-rank test.
* a logistic GLM (prevention ~ window + threshold + scope) when statsmodels is
  installed (optional).

Survival math (KM, log-rank) is implemented on numpy so this runs with only
pandas/numpy/matplotlib/scipy. Install ``research/requirements-analysis.txt``
for the optional GLM.

    PYTHONPATH=. python3 -m research.analyze research/out/rows.csv --outdir research/out
"""

from __future__ import annotations

import argparse
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

_BOOL_COLS = ["detected", "attack_reached_exfil", "is_benign", "false_positive",
              "detected_before_first_exfil"]


def load(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    for col in _BOOL_COLS:
        if col in df:
            df[col] = df[col].map({"True": True, "False": False, True: True, False: False})
    for col in ["window_seconds", "threshold", "time_to_first_exfil", "time_to_detect",
                "time_to_contain", "prevented_fraction", "episode_duration_s", "api_cost_usd"]:
        if col in df:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    return df


def _safe_nanmean(values) -> float:
    arr = np.asarray(values, dtype=float)
    arr = arr[~np.isnan(arr)]
    return float(arr.mean()) if arr.size else float("nan")


def _bootstrap_ci(values: np.ndarray, stat=np.mean, n: int = 2000, seed: int = 0):
    values = np.asarray(values, dtype=float)
    values = values[~np.isnan(values)]
    if len(values) == 0:
        return (np.nan, np.nan, np.nan)
    rng = np.random.default_rng(seed)
    boots = [stat(rng.choice(values, size=len(values), replace=True)) for _ in range(n)]
    return (float(stat(values)), float(np.percentile(boots, 2.5)), float(np.percentile(boots, 97.5)))


def summarize(df: pd.DataFrame) -> pd.DataFrame:
    attack = df[~df["is_benign"]]
    benign = df[df["is_benign"]]
    rows = []
    cells = df[["scope", "window_seconds", "threshold", "defender_label"]].drop_duplicates()
    for _, cell in cells.iterrows():
        key = ((df["scope"] == cell["scope"]) & (df["window_seconds"] == cell["window_seconds"])
               & (df["threshold"] == cell["threshold"]))
        a = attack[key[attack.index]]
        b = benign[key[benign.index]]
        det, det_lo, det_hi = _bootstrap_ci(a["detected"].astype(float).values)
        cbe, cbe_lo, cbe_hi = _bootstrap_ci(
            a.loc[a["attack_reached_exfil"], "detected_before_first_exfil"].astype(float).values)
        prev, prev_lo, prev_hi = _bootstrap_ci(a["prevented_fraction"].values)
        fpr, fpr_lo, fpr_hi = _bootstrap_ci(b["false_positive"].astype(float).values) if len(b) else (np.nan,)*3
        rows.append({
            "scope": cell["scope"], "window_seconds": cell["window_seconds"],
            "threshold": cell["threshold"], "n_attack": len(a), "n_benign": len(b),
            "detection_rate": det, "detection_rate_lo": det_lo, "detection_rate_hi": det_hi,
            "contained_before_exfil_rate": cbe, "cbe_lo": cbe_lo, "cbe_hi": cbe_hi,
            "mean_prevented_fraction": prev, "prev_lo": prev_lo, "prev_hi": prev_hi,
            "false_positive_rate": fpr, "fpr_lo": fpr_lo, "fpr_hi": fpr_hi,
            "mean_time_to_detect": _safe_nanmean(a["time_to_detect"].values),
        })
    return pd.DataFrame(rows).sort_values(["scope", "window_seconds", "threshold"])


def plot_operating_curve(summary: pd.DataFrame, out_path: str) -> None:
    # Detection rate vs. false-positive rate — the ROC-style operating curve.
    # Robust whether or not episodes reach exfiltration (unlike a prevention
    # metric), so it works for safety-bounded attacker telemetry too.
    fig, ax = plt.subplots(figsize=(7, 5.5))
    ax.plot([0, 1], [0, 1], linestyle=":", color="gray", alpha=0.5, label="chance")
    for scope, grp in summary.groupby("scope"):
        grp = grp.sort_values("false_positive_rate")
        ax.plot(grp["false_positive_rate"], grp["detection_rate"],
                marker="o", linestyle="-", label=f"scope={scope}", alpha=0.85)
    ax.set_xlabel("False-positive rate  (benign episodes flagged)")
    ax.set_ylabel("Detection rate  (attack episodes detected)")
    ax.set_title("Defender operating curve: detection vs. false positives")
    ax.set_xlim(-0.02, 1.02); ax.set_ylim(-0.02, 1.02)
    ax.grid(True, alpha=0.3); ax.legend()
    fig.tight_layout(); fig.savefig(out_path, dpi=130); plt.close(fig)


def kaplan_meier(durations: np.ndarray, observed: np.ndarray):
    """Return (times, survival) for a KM estimate. observed=1 event, 0 censored."""
    order = np.argsort(durations)
    d, o = np.asarray(durations)[order], np.asarray(observed)[order]
    n = len(d)
    times, surv, s, at_risk = [], [], 1.0, n
    i = 0
    while i < n:
        t = d[i]
        same = d == t
        events = int(np.sum(o[same]))
        if events > 0:
            s *= (1 - events / at_risk)
            times.append(t); surv.append(s)
        at_risk -= int(np.sum(same))
        i += int(np.sum(same))
    return np.array([0.0] + times), np.array([1.0] + surv)


def logrank_test(d1, o1, d2, o2) -> float:
    """Two-group log-rank chi-square -> p-value (scipy chi2, 1 df)."""
    from scipy.stats import chi2
    d1, o1, d2, o2 = map(np.asarray, (d1, o1, d2, o2))
    times = np.unique(np.concatenate([d1[o1 == 1], d2[o2 == 1]]))
    obs1 = exp1 = var = 0.0
    for t in times:
        n1 = np.sum(d1 >= t); n2 = np.sum(d2 >= t); n = n1 + n2
        if n == 0:
            continue
        o_1 = np.sum((d1 == t) & (o1 == 1))
        o_t = o_1 + np.sum((d2 == t) & (o2 == 1))
        obs1 += o_1
        exp1 += o_t * n1 / n
        if n > 1:
            var += o_t * (n1 / n) * (n2 / n) * (n - o_t) / (n - 1)
    if var == 0:
        return float("nan")
    stat = (obs1 - exp1) ** 2 / var
    return float(chi2.sf(stat, df=1))


def plot_km_time_to_contain(df: pd.DataFrame, out_path: str) -> str:
    """KM of time-to-containment by scope at the modal (window, threshold) cell."""
    attack = df[~df["is_benign"]].copy()
    if attack.empty:
        return "no attack episodes"
    w = attack["window_seconds"].median()
    t = attack["threshold"].median()
    cell = attack[(attack["window_seconds"] == w) & (attack["threshold"] == t)]
    fig, ax = plt.subplots(figsize=(7, 5))
    groups = {}
    for scope, grp in cell.groupby("scope"):
        dur = grp["time_to_contain"].fillna(grp["episode_duration_s"]).values
        obs = grp["time_to_contain"].notna().astype(int).values
        times, surv = kaplan_meier(dur, obs)
        ax.step(times, surv, where="post", label=f"scope={scope} (n={len(grp)})")
        groups[scope] = (dur, obs)
    ax.set_xlabel("Time since episode start (s)")
    ax.set_ylabel("P(host still uncontained)")
    ax.set_title(f"Time-to-containment (window={w:g}s, threshold={t:g})")
    ax.set_ylim(-0.02, 1.02); ax.grid(True, alpha=0.3); ax.legend()
    fig.tight_layout(); fig.savefig(out_path, dpi=130); plt.close(fig)
    if set(groups) >= {"host", "global"}:
        p = logrank_test(*groups["host"], *groups["global"])
        return f"log-rank host vs global (time-to-containment): p={p:.4g}"
    return "need both scopes for a log-rank test"


def e1_detectability_by_autonomy(df: pd.DataFrame, scope: str = "host",
                                 window=None, threshold=None):
    """E1: at a fixed operating point, does detection rate differ by attacker
    autonomy class (scripted vs llm)? Returns a per-class table (rate + bootstrap
    95% CI) and a chi-square p-value for detection-depends-on-autonomy."""
    from scipy.stats import chi2_contingency
    attack = df[~df["is_benign"]].copy()
    if attack.empty or "autonomy" not in attack:
        return None, None
    w = window if window is not None else float(attack["window_seconds"].median())
    t = threshold if threshold is not None else float(attack["threshold"].median())
    cell = attack[(attack["window_seconds"] == w) & (attack["threshold"] == t)
                  & (attack["scope"] == scope)]
    rows, contingency = [], []
    for aut, grp in cell.groupby("autonomy"):
        det = grp["detected"].astype(float).values
        m, lo, hi = _bootstrap_ci(det)
        rows.append({"autonomy": aut, "n": len(grp), "detection_rate": m,
                     "ci_lo": lo, "ci_hi": hi})
        pos = int(grp["detected"].astype(bool).sum())
        contingency.append([pos, len(grp) - pos])
    summary = pd.DataFrame(rows)
    p = None
    if len(contingency) >= 2 and all(sum(r) > 0 for r in contingency):
        try:
            p = float(chi2_contingency(contingency)[1])
        except Exception:  # noqa: BLE001
            p = None
    return summary, {"window": w, "threshold": t, "scope": scope, "chi2_p": p}


def try_glm(df: pd.DataFrame) -> str:
    try:
        import statsmodels.formula.api as smf
    except ImportError:
        return ("logistic GLM skipped (statsmodels not installed; "
                "pip install -r research/requirements-analysis.txt)")
    a = df[~df["is_benign"]].copy()
    a["prevented_any"] = (pd.to_numeric(a["n_exfil_prevented"], errors="coerce") > 0).astype(int)
    a["scope_global"] = (a["scope"] == "global").astype(int)
    try:
        model = smf.logit("prevented_any ~ window_seconds + threshold + scope_global", data=a).fit(disp=0)
        return "logistic GLM: prevented_any ~ window + threshold + scope\n" + str(model.summary2().tables[1])
    except Exception as exc:  # noqa: BLE001
        return f"GLM failed: {exc!r}"


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("rows_csv")
    p.add_argument("--outdir", default="research/out")
    args = p.parse_args()
    figdir = os.path.join(args.outdir, "figures")
    os.makedirs(figdir, exist_ok=True)

    df = load(args.rows_csv)
    n_ep = df["episode_id"].nunique()
    print(f"loaded {len(df)} rows across {n_ep} episodes, "
          f"{df['is_benign'].sum() // max(1, df['defender_label'].nunique())} benign episodes")

    summary = summarize(df)
    summary_path = os.path.join(args.outdir, "summary_by_cell.csv")
    summary.to_csv(summary_path, index=False)
    print(f"wrote {summary_path}")

    oc = os.path.join(figdir, "operating_curve.png")
    plot_operating_curve(summary, oc); print(f"wrote {oc}")
    km = os.path.join(figdir, "km_time_to_contain.png")
    print(plot_km_time_to_contain(df, km)); print(f"wrote {km}")

    if "autonomy" in df:
        e1, meta = e1_detectability_by_autonomy(df)
        if e1 is not None and not e1.empty:
            e1.to_csv(os.path.join(args.outdir, "e1_detectability_by_autonomy.csv"), index=False)
            print(f"\nE1 detectability by autonomy "
                  f"(scope={meta['scope']}, window={meta['window']:g}s, threshold={meta['threshold']:g}):")
            for _, r in e1.iterrows():
                print(f"   {r['autonomy']:>8}: detect={r['detection_rate']:.2f} "
                      f"[{r['ci_lo']:.2f},{r['ci_hi']:.2f}] (n={int(r['n'])})")
            if meta["chi2_p"] is not None:
                print(f"   chi-square (detection depends on autonomy): p={meta['chi2_p']:.4g}")

    print("\n" + try_glm(df))


if __name__ == "__main__":
    main()
