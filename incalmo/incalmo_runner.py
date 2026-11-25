import asyncio
import os
from incalmo.core.strategies.strategy_factory import StrategyFactory
from config.attacker_config import AttackerConfig

TIMEOUT_SECONDS = 75 * 60
# Inter-step pacing: the delay between successive strategy.main() calls, i.e.
# how fast the SAME sequence of actions is spread over wall-clock time.
# Strategy-agnostic and content-free - it changes only WHEN an already-decided
# action runs, never WHAT it does. Default matches the original hardcoded
# value exactly, so leaving it unset is a no-op. Overriding it (research/grid.py
# TEMPO_DELAYS_S) is the detector's "low-and-slow" robustness ablation: does
# detection hold as the same attack is stretched across more wall-clock time
# relative to the sliding window, the complementary axis to varying the
# window itself.
STEP_DELAY_S = float(os.environ.get("INCALMO_STEP_DELAY_S", "0.5"))

strategy_factory = StrategyFactory()


async def run_incalmo_strategy(config: AttackerConfig, task_id: str):
    """Run incalmo with the specified strategy"""
    strategy = strategy_factory.build_strategy(config, task_id)

    await strategy.initialize()

    start_time = asyncio.get_event_loop().time()

    while True:
        result = await strategy.main()
        if result:
            break
        if asyncio.get_event_loop().time() - start_time > TIMEOUT_SECONDS:
            break
        await asyncio.sleep(STEP_DELAY_S)
