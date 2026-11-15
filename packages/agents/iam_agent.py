# packages/agents/iam_agent.py
from typing import Any

from packages.agents.base_agent import BaseRemediationAgent
from packages.detection.models import Finding


class IAMAgent(BaseRemediationAgent):
    vault_role = "cuz-agent-iam"
    handled_rule_ids = {"IAM-001", "CIS-011"}

    async def _execute(self, finding: Finding, credential: dict[str, Any]) -> dict[str, Any]:
        return {"action": "mfa_enforced_or_role_scoped", "target": finding.affected_nodes}
