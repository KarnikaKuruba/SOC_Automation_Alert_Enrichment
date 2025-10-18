"""SOC Automation - Alert Enrichment (sample)
Usage:
  python main.py sample_alerts.json results/enriched_alerts.json
Description:
  - Reads alerts JSON, enriches IPs/domains using threat_intel_api.simulate_enrich(),
    writes enriched output to results file and a simple CSV summary.
"""
import sys, json, csv
from threat_intel_api import simulate_enrich

def enrich_alerts(input_file, output_file, csv_file):
    with open(input_file) as f:
        alerts = json.load(f)
    enriched = []
    with open(csv_file, 'w', newline='') as cf:
        writer = csv.writer(cf)
        writer.writerow(['alert_id','src_ip','dst_ip','threat_score','tags'])
        for a in alerts:
            info = simulate_enrich(a)
            enriched.append(info)
            writer.writerow([info.get('id'), info.get('src_ip'), info.get('dst_ip'),
                             info.get('threat_score'), ';'.join(info.get('tags', []))])
    with open(output_file, 'w') as f:
        json.dump(enriched, f, indent=2)
    print(f"Wrote enriched alerts to {output_file} and summary to {csv_file}")

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: python main.py <input.json> <output.json> <summary.csv>")
        sys.exit(1)
    enrich_alerts(sys.argv[1], sys.argv[2], sys.argv[3])
