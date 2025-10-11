from datetime import datetime

from fpdf import FPDF


def generate_pdf_report(alerts: list, filename: str = "report.pdf") -> None:
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, f"Logs analysis report (SIEM-lite) for day: {datetime.now().date()}", ln=True)

    pdf.set_font("Arial", "", 12)
    if not alerts:
        pdf.cell(0, 10, "No suspicious events.")
    else:
        pdf.ln(5)
        for idx, (alert_type, message) in enumerate(alerts, start=1):
            pdf.set_font("Arial", "B", 12)
            pdf.multi_cell(0, 10, f"{idx}. {alert_type}")
            pdf.set_font("Arial", "", 10)
            pdf.multi_cell(0, 6, f"\t\t\t\t- {message}\n")

    pdf.output(filename)
    print(f"Report saved to: {filename}")
