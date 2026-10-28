from typing import Dict, List, Optional
from src.models import AlertSeverity, BeaconAlert, FlowRecord
from src.rules.base import BaseRule
from src.rules.entropy import HighEntropyChannelRule
from src.rules.jitter import JitterBeaconRule
from src.rules.periodic import PeriodicBeaconRule
from src.rules.port import NonStandardPortRule

SEVERITY_WEIGHTS: Dict[AlertSeverity, int] = {
    AlertSeverity.INFO: 0,
    AlertSeverity.LOW: 1,
    AlertSeverity.MEDIUM: 2,
    AlertSeverity.HIGH: 3,
    AlertSeverity.CRITICAL: 4,
}


class RuleEngine:
    """Multi-rule evaluation orchestrator and alert deduplication manager."""

    def __init__(self, register_defaults: bool = True):
        self.rules: List[BaseRule] = []
        if register_defaults:
            self._register_default_rules()

    def _register_default_rules(self) -> None:
        self.rules.extend([
            PeriodicBeaconRule(),
            JitterBeaconRule(),
            HighEntropyChannelRule(),
            NonStandardPortRule(),
        ])

    def register_rule(self, rule: BaseRule) -> None:
        """Registers an active detection rule instance."""
        self.rules.append(rule)

    def evaluate_flow(self, flow: FlowRecord) -> List[BeaconAlert]:
        """Evaluates all enabled rules against a single flow record."""
        alerts: List[BeaconAlert] = []
        for rule in self.rules:
            if not rule.enabled:
                continue
            alert = rule.evaluate(flow)
            if alert is not None:
                alerts.append(alert)
        return alerts

    def evaluate_flows(
        self,
        flows: List[FlowRecord],
        deduplicate: bool = True,
    ) -> List[BeaconAlert]:
        """Evaluates a batch of flows, optionally deduplicating multiple alerts per flow ID."""
        all_alerts: List[BeaconAlert] = []
        for flow in flows:
            flow_alerts = self.evaluate_flow(flow)
            all_alerts.extend(flow_alerts)

        if deduplicate:
            return self.deduplicate_alerts(all_alerts)
        return all_alerts

    @staticmethod
    def deduplicate_alerts(alerts: List[BeaconAlert]) -> List[BeaconAlert]:
        """Deduplicates alerts by flow_id, selecting the highest-severity alert

        and merging concurrent MITRE ATT&CK detection context.
        """
        if not alerts:
            return []

        deduped: Dict[str, BeaconAlert] = {}

        for alert in alerts:
            fid = alert.flow_id
            if fid not in deduped:
                deduped[fid] = alert
            else:
                existing = deduped[fid]
                existing_weight = SEVERITY_WEIGHTS.get(existing.severity, 0)
                incoming_weight = SEVERITY_WEIGHTS.get(alert.severity, 0)

                if incoming_weight > existing_weight:
                    merged_desc = (
                        f"{alert.description} | Correlated technique: "
                        f"{existing.mitre_attack.technique_id} ({existing.mitre_attack.technique_name})"
                    )
                    updated = alert.model_copy(update={"description": merged_desc})
                    deduped[fid] = updated
                else:
                    merged_desc = (
                        f"{existing.description} | Correlated technique: "
                        f"{alert.mitre_attack.technique_id} ({alert.mitre_attack.technique_name})"
                    )
                    updated = existing.model_copy(update={"description": merged_desc})
                    deduped[fid] = updated

        return list(deduped.values())
    