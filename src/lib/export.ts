import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";

export function downloadCsv(filename: string, headers: string[], rows: (string | number | null | undefined)[][]) {
  const all = [headers, ...rows];
  const csv = all
    .map(r => r.map(c => `"${String(c ?? "").replace(/"/g, '""')}"`).join(","))
    .join("\n");
  const blob = new Blob(["\uFEFF" + csv], { type: "text/csv;charset=utf-8;" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

export function downloadPdf(opts: {
  filename: string;
  title: string;
  subtitle?: string;
  sections: Array<{ heading: string; headers: string[]; rows: (string | number | null | undefined)[][] }>;
}) {
  const doc = new jsPDF({ orientation: "landscape", unit: "pt" });
  const now = new Date().toLocaleString();

  // Header band
  doc.setFillColor(15, 23, 42);
  doc.rect(0, 0, doc.internal.pageSize.getWidth(), 70, "F");
  doc.setTextColor(56, 224, 224);
  doc.setFontSize(18);
  doc.text("CyberGita OSINT Report", 40, 32);
  doc.setTextColor(180, 200, 220);
  doc.setFontSize(10);
  doc.text(opts.title, 40, 50);
  doc.setFontSize(8);
  doc.text(`Generated: ${now}`, doc.internal.pageSize.getWidth() - 200, 50);

  let cursorY = 90;
  if (opts.subtitle) {
    doc.setTextColor(50);
    doc.setFontSize(10);
    doc.text(opts.subtitle, 40, cursorY);
    cursorY += 16;
  }

  for (const sec of opts.sections) {
    doc.setFontSize(12);
    doc.setTextColor(30, 60, 90);
    doc.text(sec.heading, 40, cursorY);
    cursorY += 6;
    autoTable(doc, {
      startY: cursorY,
      head: [sec.headers],
      body: sec.rows.map(r => r.map(c => String(c ?? "—"))),
      styles: { fontSize: 8, cellPadding: 4 },
      headStyles: { fillColor: [15, 23, 42], textColor: [180, 230, 240] },
      alternateRowStyles: { fillColor: [245, 248, 252] },
      margin: { left: 40, right: 40 },
    });
    // @ts-expect-error lastAutoTable injected by autotable
    cursorY = (doc.lastAutoTable?.finalY ?? cursorY) + 24;
  }

  const pages = doc.getNumberOfPages();
  for (let i = 1; i <= pages; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(120);
    doc.text(`Page ${i} / ${pages} · CyberGita OSINT`, 40, doc.internal.pageSize.getHeight() - 20);
  }
  doc.save(opts.filename);
}
