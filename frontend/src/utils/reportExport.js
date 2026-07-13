import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";

export async function generatePDFReport(findings, summary, providerName, framework) {
  const doc = new jsPDF();
  const now = new Date().toLocaleString();
  const pageWidth = doc.internal.pageSize.getWidth();

  // Header
  doc.setFillColor(15, 23, 42); // slate-950
  doc.rect(0, 0, pageWidth, 40, "F");
  doc.setTextColor(16, 185, 129); // emerald-500
  doc.setFontSize(22);
  doc.text("CloudSecure", 14, 20);
  doc.setFontSize(10);
  doc.setTextColor(148, 163, 184); // slate-400
  doc.text("Cloud Security Posture Management Report", 14, 28);
  doc.text(now, 14, 35);

  // Provider info
  doc.setTextColor(30, 41, 59);
  doc.setFontSize(12);
  doc.text(`Provider: ${providerName}`, 14, 50);
  if (framework) {
    doc.text(`Framework: ${framework}`, 14, 57);
  }

  // Summary
  const totalOpen = summary?.total_open ?? findings.length;
  const critical = summary?.by_severity?.CRITICAL || findings.filter((f) => f.severity === "CRITICAL").length;
  const high = summary?.by_severity?.HIGH || findings.filter((f) => f.severity === "HIGH").length;
  const medium = summary?.by_severity?.MEDIUM || findings.filter((f) => f.severity === "MEDIUM").length;
  const low = summary?.by_severity?.LOW || findings.filter((f) => f.severity === "LOW").length;

  const summaryY = framework ? 67 : 60;
  doc.setFontSize(14);
  doc.setTextColor(15, 23, 42);
  doc.text("Executive Summary", 14, summaryY);

  doc.setFontSize(10);
  doc.setTextColor(71, 85, 105);
  const summaryLines = [
    `Total Open Findings: ${totalOpen}`,
    `Critical: ${critical}  |  High: ${high}  |  Medium: ${medium}  |  Low: ${low}`,
  ];
  summaryLines.forEach((line, i) => {
    doc.text(line, 14, summaryY + 8 + i * 6);
  });

  // Findings table
  const tableY = summaryY + 25;
  doc.setFontSize(14);
  doc.setTextColor(15, 23, 42);
  doc.text("Findings Detail", 14, tableY);

  const tableData = findings.map((f) => [
    f.severity,
    f.rule_id || "",
    (f.rule_name || "").substring(0, 60),
    f.resource_type || "",
    (f.arn || "").split("/").pop() || (f.arn || "").substring(0, 30),
    Array.isArray(f.compliance_frameworks) ? f.compliance_frameworks.join(", ") : "",
    (f.remediation_steps || "").substring(0, 80),
  ]);

  autoTable(doc, {
    startY: tableY + 4,
    head: [["Severity", "Rule ID", "Issue", "Type", "Resource", "Frameworks", "Remediation"]],
    body: tableData,
    theme: "striped",
    headStyles: {
      fillColor: [15, 23, 42],
      textColor: [16, 185, 129],
      fontSize: 7,
      fontStyle: "bold",
    },
    bodyStyles: {
      fontSize: 6.5,
      textColor: [51, 65, 85],
    },
    alternateRowStyles: {
      fillColor: [241, 245, 249],
    },
    columnStyles: {
      0: { cellWidth: 16, fontStyle: "bold" },
      1: { cellWidth: 22 },
      2: { cellWidth: 40 },
      3: { cellWidth: 20 },
      4: { cellWidth: 25 },
      5: { cellWidth: 20 },
      6: { cellWidth: 38 },
    },
    margin: { left: 14, right: 14 },
    didParseCell: (data) => {
      if (data.section === "body" && data.column.index === 0) {
        const val = data.cell.raw;
        if (val === "CRITICAL") data.cell.styles.textColor = [239, 68, 68];
        else if (val === "HIGH") data.cell.styles.textColor = [249, 115, 22];
        else if (val === "MEDIUM") data.cell.styles.textColor = [234, 179, 8];
        else if (val === "LOW") data.cell.styles.textColor = [96, 165, 250];
      }
    },
  });

  // Footer on each page
  const pageCount = doc.internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(148, 163, 184);
    doc.text(
      `CloudSecure Report - Page ${i} of ${pageCount} - Generated ${now}`,
      14,
      doc.internal.pageSize.getHeight() - 10
    );
  }

  const filename = `cloudsecure_report_${framework || "all"}_${new Date().toISOString().slice(0, 10)}.pdf`;
  doc.save(filename);
}

export function generateCSVReport(findings, providerName, framework) {
  const headers = [
    "Severity",
    "Rule ID",
    "Issue",
    "Resource Type",
    "Resource ARN",
    "Compliance Frameworks",
    "Status",
    "First Seen",
    "Remediation Steps",
  ];

  const escapeCSV = (val) => {
    const str = String(val ?? "");
    if (str.includes(",") || str.includes('"') || str.includes("\n")) {
      return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
  };

  const rows = findings.map((f) => [
    f.severity,
    f.rule_id,
    f.rule_name,
    f.resource_type,
    f.arn,
    Array.isArray(f.compliance_frameworks) ? f.compliance_frameworks.join("; ") : "",
    f.status,
    f.first_seen || "",
    f.remediation_steps || "",
  ]);

  const csv = [
    `# CloudSecure Security Report`,
    `# Provider: ${providerName}`,
    `# Framework: ${framework || "All"}`,
    `# Generated: ${new Date().toISOString()}`,
    `# Total Findings: ${findings.length}`,
    "",
    headers.map(escapeCSV).join(","),
    ...rows.map((row) => row.map(escapeCSV).join(",")),
  ].join("\n");

  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `cloudsecure_findings_${framework || "all"}_${new Date().toISOString().slice(0, 10)}.csv`;
  link.click();
  URL.revokeObjectURL(url);
}
