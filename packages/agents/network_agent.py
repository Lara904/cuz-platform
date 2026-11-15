# packages/agents/network_agent.py
from typing import Any

from packages.agents.base_agent import BaseRemediationAgent
from packages.detection.models import Finding


class NetworkAgent(BaseRemediationAgent):
    vault_role = "cuz-agent-network"
    handled_rule_ids = {"NET-001", "STORAGE-PUBLIC-001"}

    async def _execute(self, finding: Finding, credential: dict[str, Any]) -> dict[str, Any]:
        return {
            "action": "security_group_rule_closed_or_bucket_privatized",
            "target": finding.affected_nodes,
        }
