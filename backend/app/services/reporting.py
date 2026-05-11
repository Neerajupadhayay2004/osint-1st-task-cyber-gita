import json
import os
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class ReportingService:
    def __init__(self, report_dir="reports"):
        self.report_dir = report_dir
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)

    def generate_json_report(self, data: dict, report_type: str) -> str:
        """
        Generates a JSON report file.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{report_type}_{timestamp}.json"
        filepath = os.path.join(self.report_dir, filename)

        try:
            with open(filepath, "w") as f:
                json.dump(data, f, indent=4)
            return filepath
        except Exception as e:
            logger.error(f"Failed to generate report: {e}")
            raise e

    def list_reports(self):
        """
        Lists all generated reports.
        """
        return os.listdir(self.report_dir)

reporting_service = ReportingService()
