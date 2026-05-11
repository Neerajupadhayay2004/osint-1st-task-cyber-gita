import pandas as pd
from fpdf import FPDF
import io
import json
from datetime import datetime
import os

class ExportService:
    def __init__(self, export_dir="exports"):
        self.export_dir = export_dir
        if not os.path.exists(self.export_dir):
            os.makedirs(self.export_dir)

    def generate_csv(self, data: list, filename: str) -> str:
        """Generates a CSV file from a list of dicts."""
        df = pd.DataFrame(data)
        filepath = os.path.join(self.export_dir, f"{filename}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        df.to_csv(filepath, index=False)
        return filepath

    def generate_pdf_report(self, report_data: dict, filename: str) -> str:
        """Generates a professional PDF report."""
        pdf = FPDF()
        pdf.add_page()
        
        # Title
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "Cyber Gita OSINT Security Report", ln=True, align="C")
        pdf.ln(10)
        
        # Metadata
        pdf.set_font("Arial", "", 10)
        pdf.cell(0, 10, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
        pdf.cell(0, 10, f"Target: {report_data.get('target', 'N/A')}", ln=True)
        pdf.ln(5)
        
        # Summary
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "1. Executive Summary", ln=True)
        pdf.set_font("Arial", "", 10)
        summary = report_data.get("summary", {})
        pdf.multi_cell(0, 10, f"Threat Level: {summary.get('threat_level', 'N/A').upper()}")
        pdf.multi_cell(0, 10, f"Threat Score: {summary.get('threat_score', 0)}")
        pdf.ln(5)
        
        # AI Intelligence
        if "ai_intelligence" in report_data:
            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 10, "2. AI Analysis & Recommendations", ln=True)
            pdf.set_font("Arial", "", 10)
            gemini = report_data["ai_intelligence"].get("gemini_report", {})
            pdf.multi_cell(0, 10, f"AI Summary: {gemini.get('summary', 'N/A')}")
            pdf.ln(2)
            pdf.set_font("Arial", "B", 10)
            pdf.cell(0, 10, "Recommendations:", ln=True)
            pdf.set_font("Arial", "", 10)
            for rec in gemini.get("recommendations", []):
                pdf.multi_cell(0, 10, f"- {rec}")
            pdf.ln(5)

        # Network Details
        if "network" in report_data:
            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 10, "3. Network Intelligence", ln=True)
            pdf.set_font("Arial", "", 10)
            network = report_data["network"]
            pdf.cell(0, 10, f"ISP: {network.get('isp', 'N/A')}", ln=True)
            pdf.cell(0, 10, f"Organization: {network.get('org', 'N/A')}", ln=True)
            pdf.cell(0, 10, f"Country: {network.get('country', 'N/A')}", ln=True)
            pdf.cell(0, 10, f"Open Ports: {', '.join(map(str, network.get('ports', [])))}", ln=True)
        
        filepath = os.path.join(self.export_dir, f"{filename}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
        pdf.output(filepath)
        return filepath

export_service = ExportService()
