import os
import tempfile
from typing import List, Tuple
from sample_data.generate_traffic import generate_synthetic_pcap
from src.pipeline import DetectionPipeline


def run_benchmark(jitter_levels: List[float]) -> List[Tuple[float, bool, float, float]]:
    """Runs the detection pipeline across increasing jitter tiers to measure detection sensitivity."""
    results = []

    with tempfile.TemporaryDirectory() as tmp_dir:
        for jitter in jitter_levels:
            pcap_path = os.path.join(tmp_dir, f"traffic_jitter_{int(jitter * 100)}.pcap")
            generate_synthetic_pcap(output_path=pcap_path, c2_jitter_pct=jitter)

            pipeline = DetectionPipeline(contamination=0.10)
            alerts = pipeline.run(pcap_path)

            detected = any("198.51.100.24" in alert["flow_id"] for alert in alerts)
            
            # Extract metrics for the C2 flow if detected
            iat_std = 0.0
            anomaly_score = 0.0
            for alert in alerts:
                if "198.51.100.24" in alert["flow_id"]:
                    iat_std = alert["iat_std"]
                    anomaly_score = alert["anomaly_score"]
                    break

            results.append((jitter, detected, iat_std, anomaly_score))

    return results


def main() -> None:
    jitter_levels = [0.0, 0.10, 0.20, 0.30, 0.40, 0.50]
    print("=" * 75)
    print(" C2 BEACON DETECTOR: RESILIENCE & JITTER EVALUATION BENCHMARK")
    print("=" * 75)
    print(f"{'Jitter %':<10} | {'Status':<12} | {'Std Dev (IAT)':<15} | {'Anomaly Score':<15}")
    print("-" * 75)

    results = run_benchmark(jitter_levels)

    for jitter, detected, iat_std, score in results:
        status_str = "[+] DETECTED" if detected else "[-] EVADED"
        pct_str = f"{int(jitter * 100)}%"
        print(f"{pct_str:<10} | {status_str:<12} | {iat_std:<15.4f} | {score:<15.4f}")

    print("=" * 75)


if __name__ == "__main__":
    main()