import os
import pytest
from sample_data.generate_traffic import generate_synthetic_pcap
from src.pipeline import DetectionPipeline


def test_end_to_end_pipeline_identifies_c2_flow(tmp_path):
    """Verify raw PCAP ingestion produces accurate beacon alerts end-to-end."""
    pcap_file = str(tmp_path / "synthetic_test.pcap")
    
    # Generate 50-packet trace (30 bursty web packets, 20 fixed 5.0s C2 beacons)
    generate_synthetic_pcap(output_path=pcap_file, c2_jitter_pct=0.0)
    assert os.path.exists(pcap_file)

    # Execute full detection pipeline
    pipeline = DetectionPipeline(contamination=0.10)
    alerts = pipeline.run(pcap_file)

    # Validate alert structure and target identification
    assert len(alerts) > 0, "Pipeline failed to detect any anomalies in synthetic trace"
    
    # Verify the C2 destination IP and port were accurately isolated
    flagged_keys = [alert["flow_id"] for alert in alerts]
    assert any("198.51.100.24" in key and "8443" in key for key in flagged_keys), (
        f"C2 flow was not flagged. Detected flows: {flagged_keys}"
    )