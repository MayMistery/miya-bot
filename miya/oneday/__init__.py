"""1-day mission (kill chain) — bounded contexts for known-vulnerability exploitation.

Kill chain flow: Recon -> Scan -> Vuln -> Exploit -> Post

Each context has:
- domain.py: Aggregate roots, entities, value objects
- service.py: Domain service orchestrating context logic
- agent.py: Claude Agent SDK sub-agent definition
"""

from miya.oneday.recon.agent import create_agent as create_recon_agent
from miya.oneday.scan.agent import create_agent as create_scan_agent
from miya.oneday.vuln.agent import create_agent as create_vuln_agent
from miya.oneday.exploit.agent import create_agent as create_exploit_agent
from miya.oneday.post.agent import create_agent as create_post_agent

__all__ = [
    "create_recon_agent",
    "create_scan_agent",
    "create_vuln_agent",
    "create_exploit_agent",
    "create_post_agent",
]
