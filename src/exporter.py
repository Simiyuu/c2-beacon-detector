import csv
import io
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.models import BeaconAlert


class AlertExporter:
    """Serializes and exports BeaconAlert incident collections into SIEM-ready formats."""

    @staticmethod
    def to_dict_list(alerts: List[BeaconAlert]) -> List[Dict[str, Any]]:
        """Converts alerts into JSON-serializable dictionaries."""
        return [alert.model_dump(mode="json") for alert in alerts]

    @staticmethod
    def to_json(alerts: List[BeaconAlert], indent: int = 2) -> str:
        """Serializes alert records into indented JSON."""
        return json.dumps(AlertExporter.to_dict_list(alerts), indent=indent)

    @staticmethod
    def to_jsonl(alerts: List[BeaconAlert]) -> str:
        """Serializes alerts into newline-delimited JSON (JSONL) for streaming SIEM ingestion."""
        lines = [json.dumps(alert.model_dump(mode="json")) for alert in alerts]
        return "\n".join(lines)

    @staticmethod
    def to_csv(alerts: List[BeaconAlert]) -> str:
        """Flattens nested alert metadata and dispersion statistics into tabular CSV."""
        if not alerts:
            return ""

        output = io.StringIO()
        fieldnames = [
            "alert_id",
            "timestamp",
            "flow_id",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol",
            "severity",
            "mitre_technique_id",
            "mitre_technique_name",
            "mitre_tactic",
            "iat_mean",
            "iat_std",
            "cv",
            "mad",
            "entropy",
            "anomaly_score",
            "description",
        ]

        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for alert in alerts:
            tech_id = (
                alert.mitre_attack.technique_id.value
                if hasattr(alert.mitre_attack.technique_id, "value")
                else str(alert.mitre_attack.technique_id)
            )

            writer.writerow({
                "alert_id": alert.alert_id,
                "timestamp": alert.timestamp.isoformat(),
                "flow_id": alert.flow_id,
                "src_ip": alert.src_ip,
                "dst_ip": alert.dst_ip,
                "src_port": alert.src_port,
                "dst_port": alert.dst_port,
                "protocol": alert.protocol,
                "severity": alert.severity.value,
                "mitre_technique_id": tech_id,
                "mitre_technique_name": alert.mitre_attack.technique_name,
                "mitre_tactic": alert.mitre_attack.tactic,
                "iat_mean": alert.jitter_metrics.iat_mean,
                "iat_std": alert.jitter_metrics.iat_std,
                "cv": alert.jitter_metrics.coefficient_of_variation,
                "mad": alert.jitter_metrics.median_absolute_deviation,
                "entropy": alert.jitter_metrics.shannon_entropy,
                "anomaly_score": alert.anomaly_score,
                "description": alert.description,
            })

        return output.getvalue()

    @staticmethod
    def save_to_file(
        alerts: List[BeaconAlert],
        output_path: str,
        fmt: Optional[str] = None,
    ) -> None:
        """Persists alerts to disk, inferring format from file extension if not provided."""
        path = Path(output_path)
        format_type = fmt.lower() if fmt else path.suffix.lstrip(".").lower()

        if format_type == "json":
            content = AlertExporter.to_json(alerts)
        elif format_type in ["jsonl", "ndjson"]:
            content = AlertExporter.to_jsonl(alerts)
        elif format_type == "csv":
            content = AlertExporter.to_csv(alerts)
        else:
            raise ValueError(f"Unsupported export format: {format_type}")

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

        