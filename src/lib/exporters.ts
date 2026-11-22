import { jsPDF } from 'jspdf';
import type { DashboardSummary, ForensicCase, Severity, ThreatAlert } from '../shared/types';

export type ExportFormat = 'csv' | 'json' | 'pdf';

function csvEscape(val: unknown): string {
  const s = String(val ?? '');
  if (s.includes(',') || s.includes('"') || s.includes('\n') || s.includes('\r')) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

export function buildCsv(headers: string[], rows: Array<Array<string | number | boolean | null | undefined>>): string {
  return [headers.map(csvEscape).join(','), ...rows.map((r) => r.map(csvEscape).join(','))].join('\n');
}

function triggerFileDownload(content: string | Blob, filename: string, mimeType: string): void {
  const blob = content instanceof Blob ? content : new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.rel = 'noopener';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function timestampSlug(): string {
  return new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
}

function createPdfBuilder(reportTitle: string, subtitle: string) {
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 15;
  const maxTextWidth = pageWidth - margin * 2;
  let y = 18;

  const drawHeader = () => {
    doc.setFillColor(11, 17, 32);
    doc.rect(0, 0, pageWidth, 28, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(13);
    doc.text('SENTINELFORGE', margin, 11);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    doc.setTextColor(148, 163, 184);
    doc.text('AI-POWERED THREAT DETECTION AND SECURITY ANALYTICS PLATFORM', margin, 16.5);
    doc.text(`Generated: ${new Date().toISOString().replace('T', ' ').slice(0, 19)} UTC`, margin, 22);

    y = 36;
    doc.setTextColor(15, 23, 42);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(14);
    doc.text(reportTitle, margin, y);
    y += 6;
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9.5);
    doc.setTextColor(71, 85, 105);
    const subLines = doc.splitTextToSize(subtitle, maxTextWidth) as string[];
    doc.text(subLines, margin, y);
    y += subLines.length * 4.5 + 3;
    doc.setDrawColor(203, 213, 225);
    doc.line(margin, y, pageWidth - margin, y);
    y += 7;
  };

  const ensureSpace = (neededMm: number) => {
    if (y + neededMm > pageHeight - 16) {
      doc.addPage();
      y = 18;
    }
  };

  const addSectionHeading = (heading: string) => {
    ensureSpace(12);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(15, 23, 42);
    doc.text(heading, margin, y);
    y += 5.5;
  };

  const addParagraph = (text: string, options?: { bold?: boolean; mono?: boolean; color?: [number, number, number]; indent?: number; size?: number }) => {
    const indent = options?.indent ?? 0;
    const size = options?.size ?? 9;
    doc.setFont(options?.mono ? 'courier' : 'helvetica', options?.bold ? 'bold' : 'normal');
    doc.setFontSize(size);
    const [r, g, b] = options?.color ?? [30, 41, 59];
    doc.setTextColor(r, g, b);
    const lines = doc.splitTextToSize(text, maxTextWidth - indent) as string[];
    ensureSpace(lines.length * 4.3 + 2);
    doc.text(lines, margin + indent, y);
    y += lines.length * 4.3 + 1.5;
  };

  const addDivider = () => {
    ensureSpace(6);
    doc.setDrawColor(226, 232, 240);
    doc.line(margin, y, pageWidth - margin, y);
    y += 5;
  };

  const finalize = (filename: string) => {
    const totalPages = doc.getNumberOfPages();
    for (let p = 1; p <= totalPages; p++) {
      doc.setPage(p);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8);
      doc.setTextColor(100, 116, 139);
      doc.text(`SENTINELFORGE Defensive Security Report`, margin, pageHeight - 8);
      doc.text(`Page ${p} of ${totalPages}`, pageWidth - margin, pageHeight - 8, { align: 'right' });
    }
    doc.save(filename);
  };

  drawHeader();
  return { addSectionHeading, addParagraph, addDivider, ensureSpace, finalize };
}

function severityRgb(sev: Severity): [number, number, number] {
  if (sev === 'Critical') return [185, 28, 28];
  if (sev === 'High') return [194, 65, 12];
  if (sev === 'Medium') return [161, 98, 7];
  return [29, 78, 216];
}

export function exportDashboardData(
  format: ExportFormat,
  data: DashboardSummary,
  severityFilter: string
): string {
  const filteredIncidents =
    severityFilter === 'ALL' ? data.recentAlerts : data.recentAlerts.filter((a) => a.severity === severityFilter);

  const slug = timestampSlug();

  if (format === 'json') {
    const filename = `sentinelforge-dashboard-summary-${slug}.json`;
    const payload = {
      generatedAt: new Date().toISOString(),
      platform: 'SENTINELFORGE',
      reportType: 'Security Dashboard Summary',
      severityFilter,
      kpis: {
        totalEventsAnalyzed: data.totalEvents,
        totalThreatsDetected: data.totalThreats,
        openAlerts: data.openAlerts,
        acknowledgedAlerts: data.acknowledgedAlerts,
        resolvedAlerts: data.resolvedAlerts,
        correlatedSequencesCount: data.correlatedSequencesCount,
        severityCounts: data.severityCounts,
      },
      categoryDistribution: data.categoryDistribution,
      trendSeries: data.trendSeries,
      topSuspiciousIps: data.topSuspiciousIps,
      recentIncidents: filteredIncidents,
      recentAuditActivity: data.recentActivity,
    };
    triggerFileDownload(JSON.stringify(payload, null, 2), filename, 'application/json;charset=utf-8');
    return `Exported dashboard JSON report (${filename}).`;
  }

  if (format === 'csv') {
    const filename = `sentinelforge-dashboard-summary-${slug}.csv`;
    const headers = [
      'Section',
      'Metric / Alert ID',
      'Severity / Category',
      'Value / Source IP',
      'Status / MITRE',
      'Timestamp',
      'Details / Evidence',
    ];
    const rows: Array<Array<string | number>> = [
      ['KPI', 'Total Events Analyzed', 'All', data.totalEvents, 'Active', new Date().toISOString(), `${data.correlatedSequencesCount} correlated sequences`],
      ['KPI', 'Total Threats Detected', 'All', data.totalThreats, `${data.openAlerts} open / ${data.acknowledgedAlerts} ack / ${data.resolvedAlerts} resolved`, new Date().toISOString(), 'Hybrid ML + Rules'],
      ['KPI', 'Critical Alerts', 'Critical', data.severityCounts.Critical, 'Severity Count', new Date().toISOString(), ''],
      ['KPI', 'High Alerts', 'High', data.severityCounts.High, 'Severity Count', new Date().toISOString(), ''],
      ['KPI', 'Medium Alerts', 'Medium', data.severityCounts.Medium, 'Severity Count', new Date().toISOString(), ''],
      ['KPI', 'Low Alerts', 'Low', data.severityCounts.Low, 'Severity Count', new Date().toISOString(), ''],
      ...data.topSuspiciousIps.map((ip) => [
        'Top Suspicious IP',
        ip.ip,
        ip.maxSeverity,
        `${ip.avgScore}% confidence`,
        `${ip.alertCount} alert(s)`,
        new Date().toISOString(),
        ip.isPublic ? 'Public Routable' : 'Private / Reserved',
      ]),
      ...filteredIncidents.map((al) => [
        'Recent Incident',
        al.id,
        `${al.severity} / ${al.category}`,
        al.sourceIp,
        `${al.status} / ${al.mitre.techniqueId}`,
        al.timestamp,
        al.description,
      ]),
    ];
    triggerFileDownload(buildCsv(headers, rows), filename, 'text/csv;charset=utf-8');
    return `Exported dashboard CSV summary (${filename}).`;
  }

  const filename = `sentinelforge-dashboard-summary-${slug}.pdf`;
  const pdf = createPdfBuilder(
    'Security Operations Dashboard Summary',
    `Active Incident Filter: ${severityFilter} | Real-time SOC snapshot from local SentinelForge store`
  );

  pdf.addSectionHeading('1. Executive Security Metrics');
  pdf.addParagraph(`Total Events Analyzed: ${data.totalEvents}   |   Total Threats Detected: ${data.totalThreats}   |   Correlated Attack Chains: ${data.correlatedSequencesCount}`);
  pdf.addParagraph(`Alert Workflow: ${data.openAlerts} Open, ${data.acknowledgedAlerts} Acknowledged, ${data.resolvedAlerts} Resolved`);
  pdf.addParagraph(`Severity Breakdown: Critical (${data.severityCounts.Critical}), High (${data.severityCounts.High}), Medium (${data.severityCounts.Medium}), Low (${data.severityCounts.Low})`);

  pdf.addDivider();
  pdf.addSectionHeading('2. Top Suspicious Source IPs');
  if (data.topSuspiciousIps.length === 0) {
    pdf.addParagraph('No suspicious IPs recorded.');
  } else {
    for (const ip of data.topSuspiciousIps) {
      pdf.addParagraph(
        `${ip.ip} — Max Severity: ${ip.maxSeverity} | ${ip.alertCount} alert(s) | Avg Confidence: ${ip.avgScore}% | Scope: ${ip.isPublic ? 'Public' : 'Private'}`,
        { mono: true, size: 8.5 }
      );
    }
  }

  pdf.addDivider();
  pdf.addSectionHeading(`3. Recent Security Incidents (${filteredIncidents.length})`);
  if (filteredIncidents.length === 0) {
    pdf.addParagraph('No recent incidents match the active severity filter.');
  } else {
    for (const al of filteredIncidents) {
      pdf.ensureSpace(22);
      pdf.addParagraph(`[${al.severity.toUpperCase()}] ${al.title}`, { bold: true, color: severityRgb(al.severity), size: 9.5 });
      pdf.addParagraph(
        `ID: ${al.id} | Status: ${al.status} | Source: ${al.sourceIp} -> ${al.destinationIp} | MITRE: ${al.mitre.tacticId} / ${al.mitre.techniqueId} | Time: ${al.timestamp}`,
        { mono: true, size: 8, indent: 2 }
      );
      pdf.addParagraph(`Evidence: ${al.description}`, { indent: 2, size: 8.5 });
      if (al.recommendations[0]) {
        pdf.addParagraph(`Recommended Action: ${al.recommendations[0]}`, { indent: 2, size: 8.5, color: [51, 65, 85] });
      }
    }
  }

  pdf.finalize(filename);
  return `Generated dashboard PDF report (${filename}).`;
}

export function exportAlertsData(
  format: ExportFormat,
  alerts: ThreatAlert[],
  filterSummary: string
): string {
  if (alerts.length === 0) {
    throw new Error('No threat alerts match the current filters to export.');
  }

  const slug = timestampSlug();

  if (format === 'json') {
    const filename = `sentinelforge-threat-alerts-${slug}.json`;
    const payload = {
      generatedAt: new Date().toISOString(),
      platform: 'SENTINELFORGE',
      reportType: 'Threat Alerts & Explainable AI Export',
      filterSummary,
      count: alerts.length,
      alerts,
    };
    triggerFileDownload(JSON.stringify(payload, null, 2), filename, 'application/json;charset=utf-8');
    return `Exported ${alerts.length} alert(s) to JSON (${filename}).`;
  }

  if (format === 'csv') {
    const filename = `sentinelforge-threat-alerts-${slug}.csv`;
    const headers = [
      'Alert ID',
      'Timestamp',
      'Severity',
      'Category',
      'Status',
      'Title',
      'Source IP',
      'Destination IP',
      'Username',
      'MITRE Tactic',
      'MITRE Technique',
      'Confidence (%)',
      'ML Probability',
      'Isolation Forest Score',
      'Analyst Feedback',
      'Top XAI Reason',
      'Recommended Action',
    ];
    const rows = alerts.map((al) => [
      al.id,
      al.timestamp,
      al.severity,
      al.category,
      al.status,
      al.title,
      al.sourceIp,
      al.destinationIp,
      al.username,
      `${al.mitre.tacticId} ${al.mitre.tacticName}`,
      `${al.mitre.techniqueId} ${al.mitre.techniqueName}`,
      al.confidence,
      al.mlProbability,
      al.anomalyScore,
      al.analystFeedback,
      al.xai.reasons[0] ?? '',
      al.recommendations[0] ?? '',
    ]);
    triggerFileDownload(buildCsv(headers, rows), filename, 'text/csv;charset=utf-8');
    return `Exported ${alerts.length} alert(s) to CSV (${filename}).`;
  }

  const filename = `sentinelforge-threat-alerts-${slug}.pdf`;
  const pdf = createPdfBuilder(
    'Threat Alerts & Explainable AI Evidence Report',
    `Filters: ${filterSummary} | Exported Alerts: ${alerts.length}`
  );

  for (const al of alerts) {
    pdf.ensureSpace(34);
    pdf.addParagraph(`[${al.severity.toUpperCase()}] ${al.title}`, {
      bold: true,
      color: severityRgb(al.severity),
      size: 10,
    });
    pdf.addParagraph(
      `Alert ID: ${al.id} | Status: ${al.status.toUpperCase()} | Confidence: ${al.confidence.toFixed(1)}% (LR ${(al.mlProbability * 100).toFixed(1)}%, IForest ${(al.anomalyScore * 100).toFixed(1)}%)`,
      { mono: true, size: 8, indent: 2 }
    );
    pdf.addParagraph(
      `Source: ${al.sourceIp} -> Target: ${al.destinationIp} | Account: ${al.username} | Timestamp: ${al.timestamp}`,
      { mono: true, size: 8, indent: 2 }
    );
    pdf.addParagraph(
      `MITRE ATT&CK: ${al.mitre.tacticId} ${al.mitre.tacticName} / ${al.mitre.techniqueId} ${al.mitre.techniqueName}`,
      { size: 8.5, indent: 2, bold: true }
    );
    pdf.addParagraph(`Evidence: ${al.description}`, { size: 8.5, indent: 2 });
    if (al.xai.reasons.length > 0) {
      pdf.addParagraph(`XAI Attribution: ${al.xai.reasons.slice(0, 2).join(' ')}`, { size: 8.5, indent: 2, color: [71, 85, 105] });
    }
    if (al.recommendations.length > 0) {
      pdf.addParagraph(`Defensive Response: ${al.recommendations[0]}`, { size: 8.5, indent: 2 });
    }
    pdf.addDivider();
  }

  pdf.finalize(filename);
  return `Generated PDF report for ${alerts.length} alert(s) (${filename}).`;
}

export function exportAnalyticsData(
  format: ExportFormat,
  payload: {
    totalEvents: number;
    alerts: ThreatAlert[];
    trendData: Array<{ bucket: string; events: number; threats: number }>;
    categoryCounts: Array<{ category: string; count: number }>;
    severityCounts: Record<Severity, number>;
    topIps: Array<{ ip: string; count: number; maxSeverity: Severity; avgConf: string }>;
    filterSummary: string;
  }
): string {
  const slug = timestampSlug();

  if (format === 'json') {
    const filename = `sentinelforge-security-analytics-${slug}.json`;
    triggerFileDownload(
      JSON.stringify(
        {
          generatedAt: new Date().toISOString(),
          platform: 'SENTINELFORGE',
          reportType: 'Security Analytics Export',
          ...payload,
        },
        null,
        2
      ),
      filename,
      'application/json;charset=utf-8'
    );
    return `Exported security analytics JSON (${filename}).`;
  }

  if (format === 'csv') {
    const filename = `sentinelforge-security-analytics-${slug}.csv`;
    const headers = ['Dimension', 'Key / Bucket', 'Count / Severity', 'Events / Avg Confidence', 'Threats / Filter Scope'];
    const rows: Array<Array<string | number>> = [
      ['Summary', 'Total Events Analyzed', payload.totalEvents, payload.alerts.length, payload.filterSummary],
      ['Severity', 'Critical', payload.severityCounts.Critical, '', payload.filterSummary],
      ['Severity', 'High', payload.severityCounts.High, '', payload.filterSummary],
      ['Severity', 'Medium', payload.severityCounts.Medium, '', payload.filterSummary],
      ['Severity', 'Low', payload.severityCounts.Low, '', payload.filterSummary],
      ...payload.categoryCounts.map((c) => ['Attack Category', c.category, c.count, '', payload.filterSummary]),
      ...payload.topIps.map((ip) => ['Suspicious IP', ip.ip, `${ip.count} (${ip.maxSeverity})`, `${ip.avgConf}%`, payload.filterSummary]),
      ...payload.trendData.map((t) => ['Hourly Trend', t.bucket, t.threats, t.events, payload.filterSummary]),
    ];
    triggerFileDownload(buildCsv(headers, rows), filename, 'text/csv;charset=utf-8');
    return `Exported security analytics CSV (${filename}).`;
  }

  const filename = `sentinelforge-security-analytics-${slug}.pdf`;
  const pdf = createPdfBuilder(
    'Security Analytics & Telemetry Summary',
    `Filters: ${payload.filterSummary} | Events Analyzed: ${payload.totalEvents} | Matching Alerts: ${payload.alerts.length}`
  );

  pdf.addSectionHeading('1. Severity Distribution');
  pdf.addParagraph(
    `Critical: ${payload.severityCounts.Critical}   |   High: ${payload.severityCounts.High}   |   Medium: ${payload.severityCounts.Medium}   |   Low: ${payload.severityCounts.Low}`
  );

  pdf.addDivider();
  pdf.addSectionHeading('2. Attack Category Breakdown');
  if (payload.categoryCounts.length === 0) {
    pdf.addParagraph('No threat categories match the selected filters.');
  } else {
    for (const c of payload.categoryCounts) {
      pdf.addParagraph(`${c.category}: ${c.count} detection(s)`, { indent: 2 });
    }
  }

  pdf.addDivider();
  pdf.addSectionHeading('3. Top Suspicious Source IPs');
  if (payload.topIps.length === 0) {
    pdf.addParagraph('No suspicious IPs match the selected filters.');
  } else {
    for (const ip of payload.topIps) {
      pdf.addParagraph(`${ip.ip} — ${ip.count} alert(s) | Max Severity: ${ip.maxSeverity} | Avg Confidence: ${ip.avgConf}%`, {
        mono: true,
        size: 8.5,
        indent: 2,
      });
    }
  }

  pdf.addDivider();
  pdf.addSectionHeading('4. Time-Series Volume vs. Threats');
  for (const t of payload.trendData) {
    pdf.addParagraph(`${t.bucket} UTC — ${t.events} events, ${t.threats} threats`, { mono: true, size: 8.5, indent: 2 });
  }

  pdf.finalize(filename);
  return `Generated security analytics PDF (${filename}).`;
}

export function exportForensicCaseData(format: ExportFormat, fcase: ForensicCase): string {
  const slug = timestampSlug();

  if (format === 'json') {
    const filename = `sentinelforge-forensics-${fcase.id}-${slug}.json`;
    triggerFileDownload(
      JSON.stringify(
        {
          generatedAt: new Date().toISOString(),
          platform: 'SENTINELFORGE',
          reportType: 'Digital Forensics Investigation Record',
          forensicCase: fcase,
        },
        null,
        2
      ),
      filename,
      'application/json;charset=utf-8'
    );
    return `Exported forensic case JSON (${filename}).`;
  }

  if (format === 'csv') {
    const filename = `sentinelforge-forensics-${fcase.id}-${slug}.csv`;
    const headers = ['Case ID', 'Record Type', 'Timestamp', 'Actor / Severity', 'Detail / Artifact'];
    const rows: Array<Array<string | number>> = [
      [fcase.id, 'Case Summary', fcase.createdAt, `${fcase.severity} / ${fcase.status}`, `${fcase.title} | SHA-256: ${fcase.evidenceSha256}`],
      ...fcase.timeline.map((t) => [fcase.id, 'Timeline Event', t.timestamp, t.actor, t.event]),
      ...fcase.notes.map((n) => [fcase.id, 'Investigator Note', n.timestamp, `${n.author} (${n.authorRole})`, n.content]),
      ...fcase.rawArtifacts.map((raw, idx) => [fcase.id, `Raw Evidence #${idx + 1}`, fcase.updatedAt, fcase.sourceIp, raw]),
    ];
    triggerFileDownload(buildCsv(headers, rows), filename, 'text/csv;charset=utf-8');
    return `Exported forensic case CSV (${filename}).`;
  }

  const filename = `sentinelforge-forensics-${fcase.id}-${slug}.pdf`;
  const pdf = createPdfBuilder(
    'Digital Forensics Investigation Record',
    `Case ID: ${fcase.id} | Alert Ref: ${fcase.alertId} | Status: ${fcase.status.toUpperCase()}`
  );

  pdf.addParagraph(`[${fcase.severity.toUpperCase()}] ${fcase.title}`, {
    bold: true,
    color: severityRgb(fcase.severity),
    size: 10.5,
  });
  pdf.addParagraph(`Source IP: ${fcase.sourceIp} | Created: ${fcase.createdAt} | Updated: ${fcase.updatedAt}`, { mono: true, size: 8.5 });
  pdf.addParagraph(`Evidence Summary: ${fcase.evidenceSummary}`);
  pdf.addParagraph(`Chain-of-Custody SHA-256: ${fcase.evidenceSha256}`, { mono: true, size: 8 });

  pdf.addDivider();
  pdf.addSectionHeading('Preserved Raw Log Artifacts');
  if (fcase.rawArtifacts.length === 0) {
    pdf.addParagraph('No raw artifacts recorded.');
  } else {
    for (const raw of fcase.rawArtifacts) {
      pdf.addParagraph(raw, { mono: true, size: 7.5, indent: 2 });
    }
  }

  pdf.addDivider();
  pdf.addSectionHeading('Investigation Timeline');
  for (const t of fcase.timeline) {
    pdf.addParagraph(`${t.timestamp} [${t.actor}] — ${t.event}`, { size: 8.5, indent: 2 });
  }

  pdf.addDivider();
  pdf.addSectionHeading(`Investigator Notes (${fcase.notes.length})`);
  if (fcase.notes.length === 0) {
    pdf.addParagraph('No investigator notes added yet.');
  } else {
    for (const n of fcase.notes) {
      pdf.addParagraph(`${n.author} (${n.authorRole}) · ${n.timestamp}`, { bold: true, size: 8.5, indent: 2 });
      pdf.addParagraph(n.content, { size: 8.5, indent: 4 });
    }
  }

  pdf.finalize(filename);
  return `Generated forensic investigation PDF (${filename}).`;
}
