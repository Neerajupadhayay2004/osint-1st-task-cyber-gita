import json
from typing import Any, Dict
from datetime import datetime
import os

class ReportingService:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate_json_report(self, data: Dict[str, Any], report_name: str) -> str:
        """Generates a JSON report and returns the file path."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{report_name}_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)
        
        report_data = {
            "report_info": {
                "name": report_name,
                "generated_at": datetime.now().isoformat(),
                "version": "1.0"
            },
            "data": data
        }
        
        with open(filepath, 'w') as f:
            json.dump(report_data, f, indent=4)
            
        return filepath

    def generate_pdf_report(self, data: Dict[str, Any], report_name: str) -> str:
        """Placeholder for PDF report generation using Jinja2 or similar."""
        # For now, we'll just return the JSON path as a mock
        return self.generate_json_report(data, report_name)

reporting_service = ReportingService()
