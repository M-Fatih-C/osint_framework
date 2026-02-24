import json
import csv
from typing import Dict, Any
from pathlib import Path

class ReportGenerator:
    def __init__(self, output_dir: str = "reports_out"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)

    def generate_json(self, job_data: Dict[str, Any], filename: str = None) -> Path:
        name = filename or f"report_{job_data['id']}.json"
        path = self.output_dir / name
        
        with open(path, "w", encoding="utf-8") as f:
            json.dump(job_data, f, indent=4)
        return path

    def generate_html(self, job_data: Dict[str, Any], filename: str = None) -> Path:
        # A simple HTML template implementation. 
        # In a real system, Jinja2 would be used extensively.
        name = filename or f"report_{job_data['id']}.html"
        path = self.output_dir / name
        
        html_content = f"""
        <html>
        <head>
            <title>OSINT Report: {job_data.get('target', 'Unknown')}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f4f4f9; }}
                h1 {{ color: #333; }}
                .module {{ background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .module h2 {{ color: #0056b3; margin-top: 0; }}
                pre {{ background: #eee; padding: 10px; border-radius: 4px; overflow-x: auto; }}
            </style>
        </head>
        <body>
            <h1>OSINT Intelligence Report</h1>
            <p><strong>Target:</strong> {job_data.get('target')} ({job_data.get('target_type')})</p>
            <p><strong>Status:</strong> {job_data.get('status')}</p>
        """
        
        if 'correlated_intel' in job_data and job_data['correlated_intel']:
            intel = job_data['correlated_intel'].get('correlations', {})
            html_content += f"""
            <div class="module">
                <h2>Correlated Intelligence</h2>
                <ul>
                    <li>Emails Found: {len(intel.get('emails_found', []))}</li>
                    <li>IPs Found: {len(intel.get('ips_found', []))}</li>
                    <li>Domains Found: {len(intel.get('domains_found', []))}</li>
                </ul>
            </div>
            """
            
        html_content += "<h2>Module Results</h2>"
        for res in job_data.get("results", []):
            module_name = res.get("module", "Unknown")
            data = json.dumps(res.get("data", {}), indent=2)
            html_content += f"""
            <div class="module">
                <h2>{module_name}</h2>
                <pre>{data}</pre>
            </div>
            """
            
        html_content += """
        </body>
        </html>
        """
        
        with open(path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return path
