import React, { useEffect, useState } from 'react';
import { ExportPrintToolbar } from '../components/ExportPrintToolbar';
import { PrintSheetHeader } from '../components/PrintLayout';
import { AlertStatusText, SeverityText, formatUtcTime } from '../components/SeverityText';
import { api } from '../lib/api';
import { exportAlertsData } from '../lib/exporters';
import type { ThreatAlert } from '../shared/types';

export const ReportsView: React.FC = () => {
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        const res = await api.getAlerts();
        setAlerts(res.alerts);
      } finally {
        setLoading(false);
      }
    };
    void load();
  }, []);

  const filtered = alerts.filter((a) => {
    if (severityFilter !== 'ALL' && a.severity !== severityFilter) return false;
    if (statusFilter !== 'ALL' && a.status !== statusFilter) return false;
    return true;
  });

  if (loading) {
    return <div className="h-64 animate-pulse border border-slate-800 bg-[#111827]" />;
  }

  const filterSummary = `Severity=${severityFilter}, Status=${statusFilter}`;

  return (
    <div className="space-y-6">
      <div className="no-print flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-slate-100">Incident Reports &amp; Export</h1>
          <p className="mt-1 text-xs text-slate-400">
            Generate structured incident reports with MITRE ATT&amp;CK mappings, evidence summaries, and recommended defensive actions.
          </p>
        </div>

        <div className="flex flex-wrap items-start gap-2">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="border border-slate-700 bg-[#111827] px-3 py-2 text-xs text-slate-200"
          >
            <option value="ALL">All Severities</option>
            <option value="Critical">Critical Only</option>
            <option value="High">High Only</option>
            <option value="Medium">Medium Only</option>
            <option value="Low">Low Only</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="border border-slate-700 bg-[#111827] px-3 py-2 text-xs text-slate-200"
          >
            <option value="ALL">All Statuses</option>
            <option value="open">Open Only</option>
            <option value="acknowledged">Acknowledged Only</option>
            <option value="resolved">Resolved Only</option>
          </select>

          <ExportPrintToolbar
            exportLabel="Export Report"
            printLabel="Print Report"
            onExport={(format) => exportAlertsData(format, filtered, filterSummary)}
            onPrint={() => window.print()}
          />
        </div>
      </div>

      {/* Screen + Print Incident Report Document */}
      <div className="print-only-light border border-slate-800 bg-[#111827] p-6 space-y-6">
        <div className="print-only-sheet">
          <PrintSheetHeader
            reportTitle="Security Incident Response Report"
            subtitle={`Applied Filters: ${filterSummary}`}
            metadata={[
              { label: 'Incidents Included', value: String(filtered.length) },
              { label: 'Critical / High', value: `${filtered.filter((a) => a.severity === 'Critical').length} / ${filtered.filter((a) => a.severity === 'High').length}` },
              { label: 'Medium / Low', value: `${filtered.filter((a) => a.severity === 'Medium').length} / ${filtered.filter((a) => a.severity === 'Low').length}` },
              { label: 'Open / Resolved', value: `${filtered.filter((a) => a.status === 'open').length} / ${filtered.filter((a) => a.status === 'resolved').length}` },
            ]}
          />
        </div>

        <div className="no-print flex flex-wrap items-start justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <h2 className="text-lg font-semibold text-slate-100">SENTINELFORGE Security Incident Report</h2>
            <p className="mt-1 text-xs text-slate-400">
              Generated {new Date().toISOString().replace('T', ' ').slice(0, 19)} UTC · {filtered.length} incident record(s)
            </p>
          </div>
          <div className="font-mono text-xs text-slate-400">Defensive SOC Analysis</div>
        </div>

        {filtered.length === 0 ? (
          <p className="py-8 text-center text-sm text-slate-500">No incident records match the selected filters.</p>
        ) : (
          <div className="divide-y divide-slate-800">
            {filtered.map((al) => (
              <div key={al.id} className="print-break-inside-avoid py-5 space-y-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                  <div className="flex items-center gap-2">
                    <SeverityText severity={al.severity} />
                    <span>·</span>
                    <span className="font-mono text-slate-400">{al.id}</span>
                    <span>·</span>
                    <span className="font-medium text-slate-300">{al.category}</span>
                  </div>
                  <AlertStatusText status={al.status} />
                </div>

                <h3 className="text-sm font-semibold text-slate-100">{al.title}</h3>
                <p className="text-xs text-slate-300">{al.description}</p>

                <div className="grid grid-cols-1 gap-2 pt-1 text-xs sm:grid-cols-3 text-slate-400">
                  <div>
                    Source / Target: <span className="font-mono text-slate-200">{al.sourceIp} → {al.destinationIp}</span>
                  </div>
                  <div>
                    MITRE ATT&amp;CK: <span className="font-mono text-violet-300">{al.mitre.tacticId} / {al.mitre.techniqueId}</span>
                  </div>
                  <div>
                    Timestamp: <span className="font-mono text-slate-300">{formatUtcTime(al.timestamp)}</span>
                  </div>
                </div>

                <div className="pt-1 text-xs">
                  <span className="font-medium text-slate-300">XAI Evidence: </span>
                  <span className="text-slate-400">{al.xai.reasons[0] ?? 'Hybrid ML + Rule Detection'}</span>
                </div>

                <div className="pt-0.5 text-xs">
                  <span className="font-medium text-slate-300">Recommended Action: </span>
                  <span className="text-slate-400">{al.recommendations[0]}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
