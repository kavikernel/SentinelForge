import React, { useState } from 'react';
import { ArrowRight, RefreshCw, Upload } from 'lucide-react';
import { HorizontalBarChart, TrendChart } from '../components/Charts';
import { ExportPrintToolbar } from '../components/ExportPrintToolbar';
import { PrintSheetHeader } from '../components/PrintLayout';
import { AlertStatusText, SeverityText, formatUtcTime } from '../components/SeverityText';
import { exportDashboardData } from '../lib/exporters';
import type { DashboardSummary, Severity } from '../shared/types';

interface DashboardViewProps {
  data: DashboardSummary | null;
  loading: boolean;
  error: string | null;
  onRefresh: () => void;
  onNavigate: (view: string, options?: { alertId?: string; severity?: string }) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  data,
  loading,
  error,
  onRefresh,
  onNavigate,
}) => {
  const [severityFilter, setSeverityFilter] = useState<'ALL' | Severity>('ALL');

  if (loading && !data) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-24 animate-pulse border border-slate-800 bg-[#111827]" />
          ))}
        </div>
        <div className="h-72 animate-pulse border border-slate-800 bg-[#111827]" />
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="border border-red-900/50 bg-[#111827] p-6">
        <h2 className="text-base font-semibold text-red-400">Unable to load dashboard telemetry</h2>
        <p className="mt-1 text-sm text-slate-400">{error ?? 'Unexpected empty server response.'}</p>
        <button
          type="button"
          onClick={onRefresh}
          className="mt-4 bg-blue-600 px-4 py-2 text-xs font-medium text-white hover:bg-blue-500"
        >
          Retry
        </button>
      </div>
    );
  }

  const filteredIncidents =
    severityFilter === 'ALL'
      ? data.recentAlerts
      : data.recentAlerts.filter((a) => a.severity === severityFilter);

  return (
    <div className="space-y-6">
      <div className="no-print flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-slate-100">Security Operations Overview</h1>
          <p className="mt-1 text-xs text-slate-400">
            Pre-populated with synthetic demonstration security events · Hybrid Isolation Forest + Logistic Regression engine
          </p>
        </div>
        <div className="flex flex-wrap items-start gap-2">
          <ExportPrintToolbar
            exportLabel="Export Summary"
            printLabel="Print Summary"
            onExport={(format) => exportDashboardData(format, data, severityFilter)}
            onPrint={() => window.print()}
          />
          <button
            type="button"
            onClick={onRefresh}
            className="inline-flex items-center gap-2 border border-slate-700 bg-[#111827] px-3.5 py-2 text-xs font-medium text-slate-200 hover:bg-slate-800 whitespace-nowrap"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            <span>Refresh</span>
          </button>
          <button
            type="button"
            onClick={() => onNavigate('logs')}
            className="inline-flex items-center gap-2 bg-blue-600 px-4 py-2 text-xs font-medium text-white hover:bg-blue-500 whitespace-nowrap"
          >
            <Upload className="h-3.5 w-3.5" />
            <span>Analyze Logs</span>
          </button>
        </div>
      </div>

      {/* Screen-Only Dashboard Content */}
      <div className="no-print space-y-6">
        {/* Top KPI Strip */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <div className="border border-slate-800 bg-[#111827] p-5">
            <div className="text-xs text-slate-400">Total Events Analyzed</div>
            <div className="mt-2 font-mono text-2xl font-semibold text-slate-100 tabular-nums">{data.totalEvents}</div>
            <div className="mt-1.5 text-xs text-slate-400">
              Correlated attack chains: <span className="font-mono text-violet-400 tabular-nums">{data.correlatedSequencesCount}</span>
            </div>
          </div>

          <div className="border border-slate-800 bg-[#111827] p-5">
            <div className="text-xs text-slate-400">Total Threats Detected</div>
            <div className="mt-2 font-mono text-2xl font-semibold text-slate-100 tabular-nums">{data.totalThreats}</div>
            <div className="mt-1.5 text-xs text-slate-400 tabular-nums">
              {data.openAlerts} open · {data.acknowledgedAlerts} acknowledged · {data.resolvedAlerts} resolved
            </div>
          </div>

          <div className="border border-slate-800 bg-[#111827] p-5">
            <div className="text-xs text-slate-400">Critical &amp; High Alerts</div>
            <div className="mt-2 font-mono text-2xl font-semibold text-red-400 tabular-nums">
              {data.severityCounts.Critical + data.severityCounts.High}
            </div>
            <div className="mt-1.5 text-xs text-slate-400 tabular-nums">
              {data.severityCounts.Critical} Critical · {data.severityCounts.High} High
            </div>
          </div>

          <div className="border border-slate-800 bg-[#111827] p-5">
            <div className="text-xs text-slate-400">Medium &amp; Low Alerts</div>
            <div className="mt-2 font-mono text-2xl font-semibold text-amber-300 tabular-nums">
              {data.severityCounts.Medium + data.severityCounts.Low}
            </div>
            <div className="mt-1.5 text-xs text-slate-400 tabular-nums">
              {data.severityCounts.Medium} Medium · {data.severityCounts.Low} Low
            </div>
          </div>
        </div>

        {/* Trend Chart + Category Distribution */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          <div className="border border-slate-800 bg-[#111827] p-5 lg:col-span-2">
            <div className="mb-4 flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold text-slate-100">Threat Detection Trend</h2>
                <p className="text-xs text-slate-400">Log volume vs. scored threat detections by UTC hour bucket</p>
              </div>
              <button
                type="button"
                onClick={() => onNavigate('analytics')}
                className="inline-flex items-center gap-1 text-xs font-medium text-blue-400 hover:text-blue-300"
              >
                <span>Full Analytics</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </button>
            </div>
            <TrendChart data={data.trendSeries} />
          </div>

          <div className="border border-slate-800 bg-[#111827] p-5">
            <div className="mb-4">
              <h2 className="text-sm font-semibold text-slate-100">Attack Category Breakdown</h2>
              <p className="text-xs text-slate-400">Classified threat distribution</p>
            </div>
            <HorizontalBarChart
              items={data.categoryDistribution.map((c, idx) => ({
                label: c.category,
                value: c.count,
                accent: idx === 0 ? 'violet' : 'blue',
              }))}
            />
          </div>
        </div>

        {/* Recent Incidents + Top Suspicious IPs & Audit Activity */}
        <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
          <div className="border border-slate-800 bg-[#111827] p-5 xl:col-span-2">
            <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-sm font-semibold text-slate-100">Recent Security Incidents</h2>
                <p className="text-xs text-slate-400">Click any incident to inspect XAI features and MITRE mapping</p>
              </div>
              <div className="flex items-center gap-1 border border-slate-800 bg-[#060913] p-0.5 text-xs">
                {(['ALL', 'Critical', 'High', 'Medium', 'Low'] as const).map((sev) => (
                  <button
                    key={sev}
                    type="button"
                    onClick={() => setSeverityFilter(sev)}
                    className={`px-2.5 py-1 transition-colors ${
                      severityFilter === sev ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {sev}
                  </button>
                ))}
              </div>
            </div>

            {filteredIncidents.length === 0 ? (
              <p className="py-8 text-center text-sm text-slate-500">No alerts match the selected severity filter.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-slate-800 text-slate-400">
                    <tr>
                      <th className="py-2.5 pr-3 font-medium">Severity</th>
                      <th className="py-2.5 pr-3 font-medium">Incident</th>
                      <th className="py-2.5 pr-3 font-medium">Source IP</th>
                      <th className="py-2.5 pr-3 font-medium">MITRE</th>
                      <th className="py-2.5 pr-3 font-medium text-right">Score</th>
                      <th className="py-2.5 font-medium text-right">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70">
                    {filteredIncidents.map((alert) => (
                      <tr
                        key={alert.id}
                        onClick={() => onNavigate('alerts', { alertId: alert.id })}
                        className="cursor-pointer transition-colors hover:bg-slate-800/40"
                      >
                        <td className="py-2.5 pr-3">
                          <SeverityText severity={alert.severity} />
                        </td>
                        <td className="py-2.5 pr-3">
                          <div className="font-medium text-slate-100">{alert.title}</div>
                          <div className="text-[11px] text-slate-400">
                            {alert.category} · {formatUtcTime(alert.timestamp)}
                          </div>
                        </td>
                        <td className="py-2.5 pr-3 font-mono text-slate-300 tabular-nums">{alert.sourceIp}</td>
                        <td className="py-2.5 pr-3 font-mono text-violet-300 whitespace-nowrap">{alert.mitre.techniqueId}</td>
                        <td className="py-2.5 pr-3 text-right font-mono text-slate-200 tabular-nums">
                          {alert.confidence.toFixed(0)}%
                        </td>
                        <td className="py-2.5 text-right">
                          <AlertStatusText status={alert.status} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="space-y-6">
            <div className="border border-slate-800 bg-[#111827] p-5">
              <div className="mb-3 flex items-center justify-between">
                <h2 className="text-sm font-semibold text-slate-100">Top Suspicious Source IPs</h2>
                <button
                  type="button"
                  onClick={() => onNavigate('intel')}
                  className="text-xs font-medium text-blue-400 hover:text-blue-300"
                >
                  Intel Lookup
                </button>
              </div>
              <div className="divide-y divide-slate-800/70">
                {data.topSuspiciousIps.map((item) => (
                  <div key={item.ip} className="flex items-center justify-between py-2.5 text-xs">
                    <div>
                      <div className="font-mono text-slate-200 tabular-nums">{item.ip}</div>
                      <div className="text-[11px] text-slate-400">
                        {item.isPublic ? 'Public' : 'Private'} · {item.alertCount} alert(s)
                      </div>
                    </div>
                    <div className="text-right">
                      <SeverityText severity={item.maxSeverity} />
                      <div className="font-mono text-[11px] text-slate-400 tabular-nums">{item.avgScore}% conf</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="border border-slate-800 bg-[#111827] p-5">
              <div className="mb-3 flex items-center justify-between">
                <h2 className="text-sm font-semibold text-slate-100">Recent Audit Activity</h2>
                <button
                  type="button"
                  onClick={() => onNavigate('audit')}
                  className="text-xs font-medium text-blue-400 hover:text-blue-300"
                >
                  Audit Log
                </button>
              </div>
              <div className="divide-y divide-slate-800/70">
                {data.recentActivity.slice(0, 5).map((entry) => (
                  <div key={entry.id} className="py-2 text-xs">
                    <div className="text-slate-200">{entry.summary}</div>
                    <div className="mt-0.5 font-mono text-[11px] text-slate-500">
                      {entry.actorUsername} ({entry.actorRole}) · {formatUtcTime(entry.timestamp)}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Print-Only Executive Security Summary Sheet */}
      <div className="print-only-sheet space-y-5">
        <PrintSheetHeader
          reportTitle="Security Operations Executive Summary"
          subtitle={`Severity Filter: ${severityFilter} | Hybrid Isolation Forest + Supervised Logistic Regression Telemetry`}
          metadata={[
            { label: 'Events Analyzed', value: String(data.totalEvents) },
            { label: 'Threats Detected', value: String(data.totalThreats) },
            { label: 'Critical / High', value: `${data.severityCounts.Critical} / ${data.severityCounts.High}` },
            { label: 'Medium / Low', value: `${data.severityCounts.Medium} / ${data.severityCounts.Low}` },
          ]}
        />

        <div className="print-break-inside-avoid">
          <h2 className="mb-2 text-xs font-bold uppercase tracking-wide">Top Suspicious Source IPs</h2>
          <table className="w-full border-collapse border border-slate-300 text-[11px]">
            <thead>
              <tr className="bg-slate-100 text-left">
                <th className="border border-slate-300 px-2.5 py-1.5">Source IP</th>
                <th className="border border-slate-300 px-2.5 py-1.5">Scope</th>
                <th className="border border-slate-300 px-2.5 py-1.5">Max Severity</th>
                <th className="border border-slate-300 px-2.5 py-1.5 text-right">Alerts</th>
                <th className="border border-slate-300 px-2.5 py-1.5 text-right">Avg Confidence</th>
              </tr>
            </thead>
            <tbody>
              {data.topSuspiciousIps.map((ip) => (
                <tr key={ip.ip}>
                  <td className="border border-slate-300 px-2.5 py-1.5 font-mono">{ip.ip}</td>
                  <td className="border border-slate-300 px-2.5 py-1.5">{ip.isPublic ? 'Public Routable' : 'Private'}</td>
                  <td className="border border-slate-300 px-2.5 py-1.5 font-semibold">{ip.maxSeverity}</td>
                  <td className="border border-slate-300 px-2.5 py-1.5 text-right font-mono">{ip.alertCount}</td>
                  <td className="border border-slate-300 px-2.5 py-1.5 text-right font-mono">{ip.avgScore}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div>
          <h2 className="mb-2 text-xs font-bold uppercase tracking-wide">
            Recent Security Incidents &amp; Evidence ({filteredIncidents.length})
          </h2>
          <div className="space-y-3">
            {filteredIncidents.map((al) => (
              <div key={al.id} className="print-break-inside-avoid border border-slate-300 p-3 text-[11px]">
                <div className="flex justify-between font-bold">
                  <span>[{al.severity.toUpperCase()}] {al.title}</span>
                  <span className="font-mono uppercase">{al.status}</span>
                </div>
                <div className="mt-1 font-mono text-[10px] text-slate-700">
                  ID: {al.id} | Source: {al.sourceIp} → {al.destinationIp} | MITRE: {al.mitre.tacticId}/{al.mitre.techniqueId} | {formatUtcTime(al.timestamp)}
                </div>
                <div className="mt-1">{al.description}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
