import json
import os
from datetime import datetime
from threading import Lock

class JSONLogger:
    def __init__(self, jsonl_file="scan_results.json", final_file="final_report_json"):
        self.jsonl_file = jsonl_file
        self.final_file = final_file
        self.lock = Lock()

    def log(self, data:dict):
        entry = {
            "timestamp": datetime.now().isoformat(),
            **data
        }

        with self.lock:
            with open(self.jsonl_file, "a") as f:
                f.write(json.dumps(entry) + '\n')
    
    def read_all(self):
        results = []
        if not os.path.exists(self.jsonl_file):
            return results
        
        with open(self.jsonl_file, 'r') as f:
            for line in f:
                results.append(json.loads(line.strip()))
        return results
    
    def build_report(self):
        raw_data = self.read_all()

        report = {
            "scan_summary": {
                "total_requests": len(raw_data),
                "total_vulnerabilities": 0,
                "timestamp": datetime.now().isoformat(),
            },
            "targets": {}
        }

        for entry in raw_data:
            url = entry.get("url")
            vuln = entry.get("vulnerability")
            if url not in report["targets"]:
                report['targets'][url] = {
                    "endpoints" : []
                }
            endpoint_data = {
                "forms": entry.get("forms"),
                "parameters": entry.get("params", []),
                "vulnerabilities" : vuln,
                "other_links": entry.get("links")
            }

            report["targets"][url]["endpoints"].append(endpoint_data)

            if vuln:
                report["scan_summary"]["total_vulnerabilities"] += 1
        return report
    

    def save_final(self):
        report = self.build_report()
        temp_file = self.final_file + ".tmp"

        with open(temp_file, "w") as f:
            json.dump(report, f, indent=4)
        
        os.replace(temp_file, self.final_file)