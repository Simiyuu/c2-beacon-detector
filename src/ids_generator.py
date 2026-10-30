import re
from typing import Dict, List, Optional, Set
from src.models import BeaconAlert


class IDSRuleGeneratorError(Exception):
    """Raised when IDS rule generation parameters or alerts are invalid."""


class IDSRuleGenerator:
    """Automated generator transforming C2 BeaconAlert instances into Suricata and Snort rules."""

    def __init__(
        self,
        base_sid: int = 1000001,
        default_action: str = "alert",
        home_net: str = "$HOME_NET",
    ) -> None:
        self.base_sid = base_sid
        self.current_sid = base_sid
        self.default_action = default_action
        self.home_net = home_net
        self._allocated_sids: Set[int] = set()

    def _get_next_sid(self, requested_sid: Optional[int] = None) -> int:
        """Allocates an unused SID, incrementing the internal pointer."""
        if requested_sid is not None:
            if requested_sid in self._allocated_sids:
                raise IDSRuleGeneratorError(f"Duplicate SID requested: {requested_sid}")
            self._allocated_sids.add(requested_sid)
            return requested_sid

        while self.current_sid in self._allocated_sids:
            self.current_sid += 1

        sid = self.current_sid
        self._allocated_sids.add(sid)
        self.current_sid += 1
        return sid

    @staticmethod
    def _sanitize_msg(msg: str) -> str:
        """Sanitizes text strings for insertion into IDS rule msg options."""
        # Remove quotes, semicolons, and backslashes that could break rule parsing
        cleaned = re.sub(r'["\\;]', "", msg)
        return cleaned.strip()

    def generate_suricata_rule(
        self,
        alert: BeaconAlert,
        sid: Optional[int] = None,
        action: Optional[str] = None,
    ) -> str:
        """Generates a production Suricata signature for a detected beacon flow."""
        act = action or self.default_action
        allocated_sid = self._get_next_sid(sid)
        proto = alert.protocol.lower()
        dst_ip = alert.dst_ip
        dst_port = alert.dst_port

        technique_id = (
            alert.mitre_attack.technique_id.value
            if hasattr(alert.mitre_attack.technique_id, "value")
            else str(alert.mitre_attack.technique_id)
        )
        safe_desc = self._sanitize_msg(alert.description or "Automated C2 Beacon")
        msg = f"C2-DETECTOR [{technique_id}] {safe_desc}"

        # Standard Suricata rule with established flow tracking and metadata
        rule = (
            f'{act} {proto} {self.home_net} any -> {dst_ip} {dst_port} '
            f'(msg:"{msg}"; '
            f'flow:established,to_server; '
            f'threshold:type limit, track by_src, count 1, seconds 60; '
            f'classtype:trojan-activity; '
            f'sid:{allocated_sid}; rev:1; '
            f'metadata:mitre_technique_id {technique_id}, anomaly_score {alert.anomaly_score};)'
        )
        return rule

    def generate_snort_rule(
        self,
        alert: BeaconAlert,
        sid: Optional[int] = None,
        action: Optional[str] = None,
    ) -> str:
        """Generates a standard Snort signature for a detected beacon flow."""
        act = action or self.default_action
        allocated_sid = self._get_next_sid(sid)
        proto = alert.protocol.lower()
        dst_ip = alert.dst_ip
        dst_port = alert.dst_port

        technique_id = (
            alert.mitre_attack.technique_id.value
            if hasattr(alert.mitre_attack.technique_id, "value")
            else str(alert.mitre_attack.technique_id)
        )
        safe_desc = self._sanitize_msg(alert.description or "Automated C2 Beacon")
        msg = f"C2-DETECTOR [{technique_id}] {safe_desc}"

        rule = (
            f'{act} {proto} {self.home_net} any -> {dst_ip} {dst_port} '
            f'(msg:"{msg}"; '
            f'flow:established,to_server; '
            f'detection_filter:track by_src, count 3, seconds 60; '
            f'classtype:trojan-activity; '
            f'sid:{allocated_sid}; rev:1;)'
        )
        return rule

    def generate_rules(
        self,
        alerts: List[BeaconAlert],
        engine: str = "suricata",
    ) -> List[str]:
        """Compiles a batch of BeaconAlert instances into rules for the target engine."""
        engine_lower = engine.lower()
        if engine_lower not in ("suricata", "snort"):
            raise IDSRuleGeneratorError(f"Unsupported IDS engine: '{engine}'. Use 'suricata' or 'snort'.")

        generator_fn = self.generate_suricata_rule if engine_lower == "suricata" else self.generate_snort_rule
        return [generator_fn(alert) for alert in alerts]

    def export_rules_text(
        self,
        alerts: List[BeaconAlert],
        engine: str = "suricata",
    ) -> str:
        """Renders rules as a newline-delimited configuration string ready for disk output."""
        rules = self.generate_rules(alerts=alerts, engine=engine)
        if not rules:
            return ""
        return "\n".join(rules) + "\n"

    def reset(self) -> None:
        """Resets SID counter and allocated set back to base_sid."""
        self.current_sid = self.base_sid
        self._allocated_sids.clear()

        