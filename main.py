import os
from rich.console import Console
from rich.table import Table

from sample_data.generate_traffic import generate_synthetic_pcap
from src.parser import PCAPParser
from src.features import FeatureExtractor
from src.detector import BeaconDetector


def main():
    console = Console()
    pcap_dir = "sample_data"
    pcap_path = os.path.join(pcap_dir, "traffic.pcap")

    # 1. Ensure synthetic traffic exists
    if not os.path.exists(pcap_path):
        console.print("[yellow][*] Generating synthetic network traffic...[/yellow]")
        os.makedirs(pcap_dir, exist_ok=True)
        generate_synthetic_pcap(pcap_path)
    else:
        console.print(f"[cyan][*] Using existing PCAP at: {pcap_path}[/cyan]")

    # 2. Parse PCAP and reconstruct flow sessions
    console.print("[yellow][*] Parsing packets and assembling bi-directional flows...[/yellow]")
    parser = PCAPParser(pcap_path)
    events = parser.parse_packets()
    flows = parser.aggregate_flows(events)
    console.print(f"[green][+] Ingested {len(events)} packets into {len(flows)} session flows.[/green]\n")

    # 3. Extract statistical timing and byte features
    console.print("[yellow][*] Extracting IAT and byte variance features...[/yellow]")
    features = FeatureExtractor.extract_all(flows)

    # 4. Run Isolation Forest anomaly detection
    console.print("[yellow][*] Running Isolation Forest detector...[/yellow]\n")
    detector = BeaconDetector(contamination=0.5)
    results = detector.fit_predict(features)

    # 5. Render output dashboard
    table = Table(title="Network Flow Anomaly Analysis Report")
    table.add_column("Flow ID / Endpoints", style="cyan", no_wrap=False)
    table.add_column("Packets", justify="right")
    table.add_column("IAT Mean (s)", justify="right")
    table.add_column("IAT StdDev", justify="right")
    table.add_column("Byte StdDev", justify="right")
    table.add_column("Score", justify="right")
    table.add_column("Classification", justify="center")

    for res in results:
        status = (
            "[bold red]ANOMALOUS (BEACON)[/bold red]"
            if res["is_beacon_anomaly"]
            else "[green]NORMAL[/green]"
        )
        table.add_row(
            res["flow_id"],
            str(res["packet_count"]),
            f"{res['iat_mean']:.3f}",
            f"{res['iat_std']:.3f}",
            f"{res['byte_std']:.3f}",
            f"{res['anomaly_score']:.4f}",
            status,
        )

    console.print(table)


if __name__ == "__main__":
    main()