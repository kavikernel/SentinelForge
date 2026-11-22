import React, { useEffect, useState } from 'react';
import { CheckCircle2, ExternalLink, FileSearch, Search, ShieldAlert, ThumbsDown, ThumbsUp } from 'lucide-react';
import { ExportPrintToolbar } from '../components/ExportPrintToolbar';
import { PrintSheetHeader } from '../components/PrintLayout';
import { AlertStatusText, SeverityText, formatUtcTime } from '../components/SeverityText';
import { api } from '../lib/api';
import { exportAlertsData } from '../lib/exporters';
import type { ThreatAlert } from '../shared/types';

interface AlertsViewProps {
  initialSelectedId?: string | null;
  onChanged: () => void;
  onOpenForensicsCase: (caseId: string) => void;
}

export const AlertsView: React.FC<AlertsViewProps> = ({
  initialSelectedId,
  onChanged,
  onOpenForensicsCase,
}) => {
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(initialSelectedId ?? null);
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('ALL');
  const [status, setStatus] = useState('ALL');
  const [loading, setLoading] = useState(true);
  const [actionBusy, setActionBusy] = useState(false);
  const [toast, setToast] = useState<string | null>(null);

  const loadAlerts = async (q = query, sev = severity, st = status) => {
    setLoading(true);
    try {
      const res = await api.getAlerts({ q, severity: sev, status: st });
      setAlerts(res.alerts);
      if (initialSelectedId && res.alerts.some((a) => a.id === initialSelectedId)) {
        setSelectedId(initialSelectedId);
      } else if (!selectedId && res.alerts.length > 0) {
        setSelectedId(res.alerts[0].id);
      } else if (selectedId && !res.alerts.some((a) => a.id === selectedId)) {
        setSelectedId(res.alerts[0]?.id ?? null);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadAlerts();
  }, [initialSelectedId]);

  const selected = alerts.find((a) => a.id === selectedId) ?? null;

  const handleStatusChange = async (id: string, nextStatus: 'open' | 'acknowledged' | 'resolved') => {
    setActionBusy(true);
    try {
      const res = await api.updateAlertStatus(id, nextStatus);
      setAlerts((prev) => prev.map((a) => (a.id === id ? res.alert : a)));
      setToast(`Alert marked as ${nextStatus} and logged to audit trail.`);
      onChanged();
    } finally {
      setActionBusy(false);
    }
  };

  const handleFeedback = async (id: string, fb: 'true_positive' | 'false_positive') => {
    setActionBusy(true);
    try {
      const res = await api.submitAlertFeedback(id, fb);
      setAlerts((prev) => prev.map((a) => (a.id === id ? res.alert : a)));
      setToast(
        `Analyst feedback recorded (${fb === 'true_positive' ? 'True Positive' : 'False Positive'}). Available for ML retraining.`
      );
      onChanged();
    } finally {
      setActionBusy(false);
    }
  };

  const handleEscalateForensics = async (alertId: string) => {
    setActionBusy(true);
    try {
      const res = await api.createForensicCaseFromAlert(alertId);
      onChanged();
      onOpenForensicsCase(res.forensicCase.id);
    } finally {
      setActionBusy(false);
    }
  };

  const filterSummary = `Severity=${severity}, Status=${status}${query ? `, Query="${query}"` : ''}`;

  return (
    <div className="space-y-6">
      <div className="no-print flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-slate-100">
            Alert Triage, MITRE ATT&amp;CK &amp; Explainable AI
          </h1>
          <p className="mt-1 text-xs text-slate-400">
            Inspect rule triggers, Isolation Forest anomaly scores, Logistic Regression feature contributions, and defensive playbooks.
          </p>
        </div>

        <ExportPrintToolbar
          exportLabel="Export Alerts"
          printLabel="Print Evidence"
          disabled={loading}
          onExport={(format) => exportAlertsData(format, alerts, filterSummary)}
          onPrint={() => window.print()}
        />
      </div>

      {toast && (
        <div className="no-print flex items-center justify-between border border-blue-500/40 bg-blue-500/10 px-4 py-2.5 text-xs text-blue-200">
          <span>{toast}</span>
          <button type="button" onClick={() => setToast(null)} className="text-blue-300 hover:text-white">
            Dismiss
          </button>
        </div>
      )}

      {/* Filter Bar */}
      <div className="no-print flex flex-wrap items-center gap-3 border border-slate-800 bg-[#111827] p-3">
        <div className="relative flex-1 min-w-[220px]">
          <Search className="pointer-events-none absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-500" />
          <input
            type="text"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              void loadAlerts(e.target.value, severity, status);
            }}
            placeholder="Filter by title, IP, MITRE technique, user..."
            className="w-full border border-slate-700 bg-[#060913] py-1.5 pl-8 pr-3 text-xs text-slate-100 focus:border-blue-500 focus:outline-none"
          />
        </div>
        <select
          value={severity}
          onChange={(e) => {
            setSeverity(e.target.value);
            void loadAlerts(query, e.target.value, status);
          }}
          className="border border-slate-700 bg-[#060913] px-3 py-1.5 text-xs text-slate-200"
        >
          <option value="ALL">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
        <select
          value={status}
          onChange={(e) => {
            setStatus(e.target.value);
            void loadAlerts(query, severity, e.target.value);
          }}
          className="border border-slate-700 bg-[#060913] px-3 py-1.5 text-xs text-slate-200"
        >
          <option value="ALL">All Statuses</option>
          <option value="open">Open</option>
          <option value="acknowledged">Acknowledged</option>
          <option value="resolved">Resolved</option>
        </select>
      </div>

      {/* Screen-Only Master-Detail Workspace */}
      <div className="no-print grid grid-cols-1 gap-6 xl:grid-cols-12">
        {/* Alert List */}
        <div className="border border-slate-800 bg-[#111827] xl:col-span-5">
          <div className="border-b border-slate-800 px-4 py-3 text-xs font-medium text-slate-300">
            Detected Threats ({alerts.length})
          </div>
          {loading ? (
            <div className="space-y-2 p-4">
              {[1, 2, 3].map((i) => (
                <div key={i} className="h-16 animate-pulse bg-slate-800/60" />
              ))}
            </div>
          ) : alerts.length === 0 ? (
            <div className="p-8 text-center text-sm text-slate-500">
              <ShieldAlert className="mx-auto mb-2 h-6 w-6 text-slate-600" />
              No alerts match the current filters.
            </div>
          ) : (
            <div className="max-h-[680px] divide-y divide-slate-800/80 overflow-y-auto">
              {alerts.map((al) => {
                const active = al.id === selected?.id;
                return (
                  <button
                    key={al.id}
                    type="button"
                    onClick={() => setSelectedId(al.id)}
                    className={`w-full px-4 py-3.5 text-left transition-colors ${
                      active ? 'bg-blue-600/15' : 'hover:bg-slate-800/40'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <SeverityText severity={al.severity} />
                      <AlertStatusText status={al.status} />
                    </div>
                    <div className="mt-1.5 text-xs font-semibold text-slate-100">{al.title}</div>
                    <div className="mt-1 flex flex-wrap items-center gap-1.5 text-[11px] text-slate-400">
                      <span className="font-mono">{al.sourceIp}</span>
                      <span>·</span>
                      <span>{al.category}</span>
                      <span>·</span>
                      <span className="font-mono text-violet-300">{al.mitre.techniqueId}</span>
                      <span>·</span>
                      <span className="font-mono tabular-nums">{al.confidence.toFixed(0)}%</span>
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Detailed XAI & Incident Playbook Pane */}
        <div className="border border-slate-800 bg-[#111827] p-6 xl:col-span-7">
          {!selected ? (
            <div className="py-16 text-center text-sm text-slate-500">
              Select a detected threat from the left list to inspect explainability details and response actions.
            </div>
          ) : (
            <div className="space-y-6">
              {/* Header & Triage Controls */}
              <div className="border-b border-slate-800 pb-5">
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-400">
                  <div className="flex items-center gap-2">
                    <SeverityText severity={selected.severity} />
                    <span>·</span>
                    <span className="font-mono">{selected.id}</span>
                    <span>·</span>
                    <span>{selected.isDemoData ? 'Synthetic Demo Data' : 'Uploaded Log Analysis'}</span>
                  </div>
                  <AlertStatusText status={selected.status} />
                </div>

                <h2 className="mt-2 text-lg font-semibold text-slate-100">{selected.title}</h2>
                <p className="mt-1.5 text-xs leading-relaxed text-slate-300">{selected.description}</p>

                <div className="mt-4 flex flex-wrap items-center gap-2">
                  {selected.status !== 'acknowledged' && selected.status !== 'resolved' && (
                    <button
                      type="button"
                      disabled={actionBusy}
                      onClick={() => void handleStatusChange(selected.id, 'acknowledged')}
                      className="border border-amber-500/50 bg-amber-500/10 px-3 py-1.5 text-xs font-medium text-amber-200 hover:bg-amber-500/20"
                    >
                      Acknowledge Alert
                    </button>
                  )}
                  {selected.status !== 'resolved' ? (
                    <button
                      type="button"
                      disabled={actionBusy}
                      onClick={() => void handleStatusChange(selected.id, 'resolved')}
                      className="inline-flex items-center gap-1.5 bg-emerald-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-emerald-500"
                    >
                      <CheckCircle2 className="h-3.5 w-3.5" />
                      <span>Mark Resolved</span>
                    </button>
                  ) : (
                    <button
                      type="button"
                      disabled={actionBusy}
                      onClick={() => void handleStatusChange(selected.id, 'open')}
                      className="border border-slate-700 px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-800"
                    >
                      Reopen Incident
                    </button>
                  )}
                  <button
                    type="button"
                    disabled={actionBusy}
                    onClick={() => void handleEscalateForensics(selected.id)}
                    className="inline-flex items-center gap-1.5 border border-blue-500/50 bg-blue-500/10 px-3 py-1.5 text-xs font-medium text-blue-200 hover:bg-blue-500/20"
                  >
                    <FileSearch className="h-3.5 w-3.5" />
                    <span>Open in Digital Forensics</span>
                  </button>
                </div>
              </div>

              {/* Metadata & MITRE ATT&CK Mapping */}
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div className="space-y-1.5 text-xs">
                  <div className="font-medium text-slate-400">Incident Telemetry</div>
                  <div className="font-mono text-slate-200">Source IP: {selected.sourceIp}</div>
                  <div className="font-mono text-slate-200">Target IP: {selected.destinationIp}</div>
                  <div className="font-mono text-slate-200">Account: {selected.username}</div>
                  <div className="font-mono text-slate-400">{formatUtcTime(selected.timestamp)}</div>
                </div>
                <div className="space-y-1.5 text-xs">
                  <div className="font-medium text-slate-400">MITRE ATT&amp;CK Mapping</div>
                  <div className="font-medium text-violet-300">
                    {selected.mitre.tacticId} · {selected.mitre.tacticName}
                  </div>
                  <div className="font-mono text-slate-200">
                    {selected.mitre.techniqueId} · {selected.mitre.techniqueName}
                  </div>
                  <a
                    href={selected.mitre.url}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 text-blue-400 hover:text-blue-300"
                  >
                    <span>MITRE ATT&amp;CK Reference</span>
                    <ExternalLink className="h-3 w-3" />
                  </a>
                </div>
              </div>

              {/* Explainable AI (XAI) Section */}
              <div className="border-t border-slate-800 pt-5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h3 className="text-sm font-semibold text-slate-100">Explainable AI (XAI) Attribution</h3>
                  <div className="font-mono text-xs text-slate-400 tabular-nums">
                    Ensemble {(selected.xai.ensembleScore * 100).toFixed(1)}% · LR {(selected.xai.logisticRegressionProb * 100).toFixed(1)}% · IForest {(selected.xai.isolationForestScore * 100).toFixed(1)}%
                  </div>
                </div>

                <ul className="mt-3 space-y-1.5 text-xs text-slate-300">
                  {selected.xai.reasons.map((r, idx) => (
                    <li key={idx} className="flex gap-2">
                      <span className="font-mono text-violet-400">-</span>
                      <span>{r}</span>
                    </li>
                  ))}
                </ul>

                <div className="mt-4 space-y-2">
                  <div className="text-xs font-medium text-slate-400">Top Contributing Model Features (Weight × Scaled Value)</div>
                  {selected.xai.featureContributions.slice(0, 6).map((fc) => {
                    const barWidth = Math.min(100, Math.max(4, Math.round(Math.abs(fc.contribution) * 35)));
                    return (
                      <div key={fc.featureName} className="grid grid-cols-12 items-center gap-2 text-xs">
                        <div className="col-span-5 truncate text-slate-300" title={fc.label}>
                          {fc.label}
                        </div>
                        <div className="col-span-2 text-right font-mono text-slate-400 tabular-nums">
                          {fc.rawValue}
                        </div>
                        <div className="col-span-3 h-2 bg-slate-800">
                          <div
                            className={`h-full ${fc.contribution >= 0 ? 'bg-violet-500' : 'bg-emerald-500'}`}
                            style={{ width: `${barWidth}%` }}
                          />
                        </div>
                        <div
                          className={`col-span-2 text-right font-mono tabular-nums ${
                            fc.contribution >= 0 ? 'text-violet-300' : 'text-emerald-400'
                          }`}
                        >
                          {fc.contribution >= 0 ? `+${fc.contribution.toFixed(2)}` : fc.contribution.toFixed(2)}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Defensive Response Recommendations */}
              <div className="border-t border-slate-800 pt-5">
                <h3 className="text-sm font-semibold text-slate-100">Recommended Defensive Response</h3>
                <ol className="mt-2.5 list-decimal space-y-1.5 pl-4 text-xs text-slate-300">
                  {selected.recommendations.map((rec, idx) => (
                    <li key={idx}>{rec}</li>
                  ))}
                </ol>
              </div>

              {/* Analyst Feedback Loop */}
              <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-800 pt-4 text-xs">
                <div>
                  <span className="font-medium text-slate-300">Detection Feedback: </span>
                  <span className="font-mono text-slate-400">
                    {selected.analystFeedback === 'unreviewed'
                      ? 'Unreviewed'
                      : selected.analystFeedback === 'true_positive'
                        ? 'Confirmed True Positive'
                        : 'Marked False Positive'}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    disabled={actionBusy}
                    onClick={() => void handleFeedback(selected.id, 'true_positive')}
                    className={`inline-flex items-center gap-1.5 border px-3 py-1.5 text-xs font-medium transition-colors ${
                      selected.analystFeedback === 'true_positive'
                        ? 'border-emerald-500 bg-emerald-500/20 text-emerald-200'
                        : 'border-slate-700 text-slate-300 hover:bg-slate-800'
                    }`}
                  >
                    <ThumbsUp className="h-3.5 w-3.5" />
                    <span>True Positive</span>
                  </button>
                  <button
                    type="button"
                    disabled={actionBusy}
                    onClick={() => void handleFeedback(selected.id, 'false_positive')}
                    className={`inline-flex items-center gap-1.5 border px-3 py-1.5 text-xs font-medium transition-colors ${
                      selected.analystFeedback === 'false_positive'
                        ? 'border-amber-500 bg-amber-500/20 text-amber-200'
                        : 'border-slate-700 text-slate-300 hover:bg-slate-800'
                    }`}
                  >
                    <ThumbsDown className="h-3.5 w-3.5" />
                    <span>False Positive</span>
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Print-Only Threat Alerts & XAI Evidence Sheet */}
      <div className="print-only-sheet space-y-5">
        <PrintSheetHeader
          reportTitle="Threat Alerts & Explainable AI Evidence Report"
          subtitle={`Applied Filters: ${filterSummary}`}
          metadata={[
            { label: 'Exported Alerts', value: String(alerts.length) },
            { label: 'Critical', value: String(alerts.filter((a) => a.severity === 'Critical').length) },
            { label: 'High', value: String(alerts.filter((a) => a.severity === 'High').length) },
            { label: 'Open / Resolved', value: `${alerts.filter((a) => a.status === 'open').length} / ${alerts.filter((a) => a.status === 'resolved').length}` },
          ]}
        />

        {alerts.map((al) => (
          <div key={al.id} className="print-break-inside-avoid border border-slate-300 p-3.5 text-[11px] space-y-1.5">
            <div className="flex justify-between font-bold">
              <span>[{al.severity.toUpperCase()}] {al.title}</span>
              <span className="font-mono uppercase">{al.status}</span>
            </div>
            <div className="font-mono text-[10px] text-slate-700">
              ID: {al.id} | {al.sourceIp} → {al.destinationIp} | Account: {al.username} | {formatUtcTime(al.timestamp)}
            </div>
            <div className="font-mono text-[10px]">
              MITRE ATT&amp;CK: {al.mitre.tacticId} {al.mitre.tacticName} / {al.mitre.techniqueId} {al.mitre.techniqueName} | Confidence: {al.confidence.toFixed(1)}%
            </div>
            <div><span className="font-semibold">Evidence:</span> {al.description}</div>
            <div><span className="font-semibold">XAI Reasons:</span> {al.xai.reasons.slice(0, 2).join(' ')}</div>
            <div><span className="font-semibold">Recommended Response:</span> {al.recommendations[0]}</div>
          </div>
        ))}
      </div>
    </div>
  );
};
