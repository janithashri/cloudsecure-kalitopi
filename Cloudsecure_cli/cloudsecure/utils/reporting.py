import csv
import os
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

def export_to_csv(results, filename="scan_report.csv"):
    keys = ["rule_id", "severity", "resource", "description", "location"]
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for res in results:
            row = {
                "rule_id": res.get("rule_id"),
                "severity": res.get("severity"),
                "resource": res.get("resource"),
                "description": res.get("rule_description") or res.get("description"),
                "location": f"{res.get('location', {}).get('filename')}:{res.get('location', {}).get('start_line')}"
            }
            writer.writerow(row)
    return filename

def export_to_pdf(results, filename="scan_report.pdf"):
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Title
    elements.append(Paragraph("CloudSecure IaC Security Audit Report", styles['Title']))
    elements.append(Paragraph(f"Team: Kaali Topi | Date: {os.popen('date /t').read()}", styles['Normal']))
    elements.append(Spacer(1, 12))

    # Table Data
    data = [["Severity", "ID", "Resource", "Description"]]
    for res in results:
        data.append([
            res.get("severity"),
            res.get("rule_id"),
            res.get("resource"),
            (res.get("rule_description") or res.get("description"))[:50] + "..." # Truncate for PDF fit
        ])

    t = Table(data)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.magenta),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    elements.append(t)
    doc.build(elements)
    return filename