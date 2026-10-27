"""fwsim -- a small teaching simulator for firewall generations.

Part I of the CS07 case study. It replays packets through a stateless
packet filter and a stateful firewall built on the same rule list, so the
five failures of stateless filtering (report Table 2.1) and the effect of
rule order can be shown with concrete packets.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "common"))
