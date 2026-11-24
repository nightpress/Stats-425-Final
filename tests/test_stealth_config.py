import unittest
from pydantic import ValidationError
from config.attacker_config import StateMachineStrategy, StealthConfig


class TestStealthConfig(unittest.TestCase):
    def test_defaults(self):
        cfg = StateMachineStrategy(name="fixture").stealth
        self.assertFalse(cfg.enabled)
        self.assertEqual(cfg.inter_action_delay, 0)
        self.assertFalse(cfg.randomized_timing)
        self.assertIsNone(cfg.scan_breadth)

    def test_nested_config(self):
        cfg = StateMachineStrategy(name="fixture", stealth={"enabled": True})
        self.assertTrue(cfg.stealth.enabled)

    def test_invalid_delay(self):
        with self.assertRaises(ValidationError):
            StealthConfig(inter_action_delay=-1)

    def test_invalid_breadth(self):
        with self.assertRaises(ValidationError):
            StealthConfig(scan_breadth=0)

    def test_independent_defaults(self):
        self.assertIsNot(StateMachineStrategy(name="fixture").stealth,
                         StateMachineStrategy(name="fixture").stealth)


if __name__ == "__main__":
    unittest.main()
