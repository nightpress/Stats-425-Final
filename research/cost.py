"""Claude API cost accounting and a hard spend cap for the episode sweep.

Two uses: (1) turn a run's ``token_usage.json`` log into a dollar figure, and
(2) a :class:`SpendLedger` the sweep checks *before* launching each episode so a
run can never blow the budget.

Prices are USD per million tokens, first-party Anthropic API rates (per the
claude-api reference, 2026). ``input_tokens`` in the usage log is LangChain's
normalized TOTAL and already includes cached tokens, so cost is computed as
uncached-input + cache-read + cache-write + output (see ``logging_service.py``).
Vendor-direct Anthropic calls may not populate a per-call ``cost``; LiteLLM/
OpenRouter do - when present those actual costs are summed and preferred.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

# per-MTok: (input, output, cache_read, cache_write)
PRICES: dict[str, tuple[float, float, float, float]] = {
    # current generation - the ones this study uses
    "claude-haiku-5-5": (0.10, 0.50, 0.01, 0.125),   # <=100K-token prompts
    "claude-sonnet-5-5": (2.00, 10.00, 0.20, 2.50),
    "claude-opus-5-5": (4.00, 20.00, 0.20, 5.00),
    # previous generation / already in the registry (for comparison runs)
    "claude-opus-5": (5.00, 25.00, 0.50, 6.25),
    "claude-sonnet-5": (2.00, 10.00, 0.20, 2.50),
    "claude-opus-4-8": (5.00, 25.00, 0.50, 6.25),
    "claude-haiku-4-5": (1.00, 5.00, 0.10, 1.25),
}
_MTOK = 1_000_000.0


def price_for(model: str) -> Optional[tuple[float, float, float, float]]:
    """Look up a price row by deployment name, tolerating a ``-litellm`` suffix."""
    if model in PRICES:
        return PRICES[model]
    base = model.replace("-litellm", "")
    return PRICES.get(base)


def call_cost(
    model: str, input_tokens: int, output_tokens: int,
    cache_read_tokens: int = 0, cache_creation_tokens: int = 0,
) -> Optional[float]:
    """Computed cost (USD) for one call, or None if the model is unpriced."""
    row = price_for(model)
    if row is None:
        return None
    in_rate, out_rate, cr_rate, cw_rate = row
    uncached_input = max(0, input_tokens - cache_read_tokens - cache_creation_tokens)
    return (
        uncached_input * in_rate
        + cache_read_tokens * cr_rate
        + cache_creation_tokens * cw_rate
        + output_tokens * out_rate
    ) / _MTOK


@dataclass
class UsageSummary:
    n_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_creation_tokens: int = 0
    reported_cost_usd: float = 0.0   # summed per-call 'cost' when the log carried it
    computed_cost_usd: float = 0.0   # from the price table
    reported_cost_available: bool = False
    models: set[str] = field(default_factory=set)

    @property
    def cost_usd(self) -> float:
        """Prefer provider-reported cost; fall back to the computed estimate."""
        return self.reported_cost_usd if self.reported_cost_available else self.computed_cost_usd

    def to_row(self) -> dict:
        return {
            "n_llm_calls": self.n_calls,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "cache_creation_tokens": self.cache_creation_tokens,
            "api_cost_usd": round(self.cost_usd, 6),
            "api_cost_source": "reported" if self.reported_cost_available else "computed",
            "models": "|".join(sorted(self.models)),
        }


def summarize_token_usage(path: str) -> UsageSummary:
    """Aggregate a ``token_usage.json`` JSONL log into a :class:`UsageSummary`.

    Returns an empty summary if the file is absent (e.g. a replayed example
    episode that carries no API log).
    """
    summary = UsageSummary()
    try:
        handle = open(path, "r", encoding="utf-8")
    except FileNotFoundError:
        return summary
    with handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            model = rec.get("model", "")
            it = int(rec.get("input_tokens", 0) or 0)
            ot = int(rec.get("output_tokens", 0) or 0)
            cr = int(rec.get("cache_read_tokens", 0) or 0)
            cc = int(rec.get("cache_creation_tokens", 0) or 0)
            summary.n_calls += 1
            summary.input_tokens += it
            summary.output_tokens += ot
            summary.cache_read_tokens += cr
            summary.cache_creation_tokens += cc
            if model:
                summary.models.add(model)
            reported = rec.get("cost")
            if reported is not None:
                summary.reported_cost_available = True
                summary.reported_cost_usd += float(reported)
            computed = call_cost(model, it, ot, cr, cc)
            if computed is not None:
                summary.computed_cost_usd += computed
    return summary


class BudgetExceeded(RuntimeError):
    """Raised when a planned spend would cross the hard cap."""


@dataclass
class SpendLedger:
    """Cumulative spend tracker with a hard cap, checked before each episode."""

    cap_usd: float
    spent_usd: float = 0.0

    @property
    def remaining_usd(self) -> float:
        return self.cap_usd - self.spent_usd

    def add(self, cost_usd: float) -> None:
        self.spent_usd += max(0.0, cost_usd)

    def check(self, planned_estimate_usd: float) -> None:
        """Raise before spending if the estimate would cross the cap."""
        if self.spent_usd + planned_estimate_usd > self.cap_usd:
            raise BudgetExceeded(
                f"planned ${planned_estimate_usd:.2f} would exceed cap "
                f"${self.cap_usd:.2f} (spent ${self.spent_usd:.2f})"
            )


def preflight(n_episodes: int, cost_per_episode_usd: float) -> dict:
    """Extrapolate total spend from a measured per-episode cost (the pilot)."""
    total = n_episodes * cost_per_episode_usd
    return {
        "n_episodes": n_episodes,
        "cost_per_episode_usd": round(cost_per_episode_usd, 4),
        "estimated_total_usd": round(total, 2),
    }
