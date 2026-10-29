import json
from pathlib import Path
import pytest
from evaluate import evaluate_c2_detector, generate_benchmark_trace, main


def test_generate_benchmark_trace_creates_valid_pcap(tmp_path: Path):
    """Verifies that synthetic benchmark generator outputs labeled ground-truth flows."""
    pcap_path = str(tmp_path / "ground_truth.pcap")
    ground_truth = generate_benchmark_trace(pcap_path)

    assert Path(pcap_path).exists()
    assert Path(pcap_path).stat().st_size > 0
    assert len(ground_truth) == 5

    malicious_count = sum(1 for is_mal in ground_truth.values() if is_mal)
    benign_count = sum(1 for is_mal in ground_truth.values() if not is_mal)
    assert malicious_count == 3
    assert benign_count == 2


def test_evaluate_c2_detector_meets_accuracy_thresholds(tmp_path: Path):
    """Verifies that C2Hunter meets minimum production classification standards."""
    pcap_path = str(tmp_path / "eval_trace.pcap")
    ground_truth = generate_benchmark_trace(pcap_path)

    results = evaluate_c2_detector(pcap_path, ground_truth)

    cm = results["confusion_matrix"]
    m = results["metrics"]
    perf = results["performance"]

    # Verify confusion matrix arithmetic
    assert cm["tp"] + cm["fp"] + cm["fn"] + cm["tn"] == len(ground_truth)
    assert cm["tp"] == 3
    assert cm["fp"] == 0

    # Production detection gates
    assert m["precision"] >= 0.90
    assert m["recall"] >= 0.90
    assert m["false_positive_rate"] <= 0.05
    assert m["f1_score"] >= 0.90

    # Telemetry and throughput checks
    assert perf["total_packets"] > 0
    assert perf["evaluation_time_sec"] >= 0.0
    assert perf["throughput_pps"] >= 0.0


def test_evaluate_main_cli_execution(tmp_path: Path, monkeypatch):
    """Verifies that evaluate.py CLI executes cleanly and persists JSON metrics."""
    pcap_path = str(tmp_path / "cli_eval.pcap")
    json_path = str(tmp_path / "scorecard.json")

    test_args = [
        "evaluate.py",
        "--output-pcap", pcap_path,
        "--json-out", json_path,
    ]
    monkeypatch.setattr("sys.argv", test_args)

    ret = main()
    assert ret == 0
    assert Path(json_path).exists()

    scorecard = json.loads(Path(json_path).read_text(encoding="utf-8"))
    assert "confusion_matrix" in scorecard
    assert "metrics" in scorecard
    assert scorecard["metrics"]["recall"] >= 0.90
    