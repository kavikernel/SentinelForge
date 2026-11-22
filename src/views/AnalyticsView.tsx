import React, { useEffect, useState } from 'react';
import { HorizontalBarChart, TrendChart } from '../components/Charts';
import { ExportPrintToolbar } from '../components/ExportPrintToolbar';
import { PrintSheetHeader } from '../components/PrintLayout';
import { SeverityText } from '../components/SeverityText';
import { api } from '../lib/api';
import { exportAnalyticsData } from '../lib/exporters';
import type { SecurityEvent, Severity, ThreatAlert } from '../shared/types';

export const AnalyticsView: React.FC = () => {
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [severityFilter, setSeverityFilter] = useState<'ALL' | Severity>('ALL');
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        const [aRes, lRes] = await Promise.all([api.getAlerts(), api.getLogs()]);
        setAlerts(aRes.alerts);
        setEvents(lRes.events);
      } finally {
        setLoading(false);
      }
    };
    void load();
  }, []);

  if (loading) {
    return <div className="h-72 animate-pulse border border-slate-800 bg-[#111827]" />;
  }

  const categories = Array.from(new Set(alerts.map((a) => a.category)));
  const filteredAlerts = alerts.filter((a) => {
    if (severityFilter !== 'ALL' && a.severity !== severityFilter) return false;
    if (categoryFilter !== 'ALL' && a.category !== categoryFilter) return false;
    return true;
  });

  // Compute trend series dynamically from filtered alerts + events
  const bucketMap = new Map<string, { events: number; threats: number }>();
  for (const ev of events) {
    const b = ev.timestamp.slice(0, 13) + ':00';
    const cur = bucketMap.get(b) ?? { events: 0, threats: 0 };
    cur.events++;
    bucketMap.set(b, cur);
  }
  for (const al of filteredAlerts) {
    const b = al.timestamp.slice(0, 13) + ':00';
    const cur = bucketMap.get(b) ?? { events: 0, threats: 0 };
    cur.threats++;
    bucketMap.set(b, cur);
  }
  const trendData = Array.from(bucketMap.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .slice(-16)
    .map(([b, v]) => ({ bucket: b.slice(5, 16).replace('T', ' '), events: v.events, threats: v.threats }));

  // Category counts
  const catCounts = new Map<string, number>();
  const sevCounts: Record<Severity, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  const ipCounts = new Map<string, { count: number; maxSeverity: Severity; totalConf: number }>();
  const sevRank = (s: Severity) => (s === 'Critical' ? 4 : s === 'High' ? 3 : s === 'Medium' ? 2 : 1);

  for (const al of filteredAlerts) {
    catCounts.set(al.category, (catCounts.get(al.category) ?? 0) + 1);
    sevCounts[al.severity]++;
    const ip = ipCounts.get(al.sourceIp) ?? { count: 0, maxSeverity: 'Low' as Severity, totalConf: 0 };
    ip.count++;
    ip.totalConf += al.confidence;
    if (sevRank(al.severity) > sevRank(ip.maxSeverity)) ip.maxSeverity = al.severity;
    ipCounts.set(al.sourceIp, ip);
  }

  const categoryBreakdown = Array.from(catCounts.entries())
    .map(([category, count]) => ({ category, count }))
    .sort((a, b) => b.count - a.count);

  const topIps = Array.from(ipCounts.entries())
    .map(([ip, st]) => ({
      ip,
      count: st.count,
      maxSeverity: st.maxSeverity,
      avgConf: (st.totalConf / st.count).toFixed(1),
    }))
    .sort((a, b) => b.count - a.count || Number(b.avgConf) - Number(a.avgConf));

  const filterSummary = `Severity=${severityFilter}, Category=${categoryFilter}`;

  return (
    <div className="space-y-6">
      <div className="no-print flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-slate-100">Security Analytics</h1>
          <p className="mt-1 text-xs text-slate-400">
            Interactive telemetry breakdown across {events.length} log events and {filteredAlerts.length} matching threat alerts
          </p>
        </div>

        <div className="flex flex-wrap items-start gap-2">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value as 'ALL' | Severity)}
            className="border border-slate-700 bg-[#111827] px-3 py-2 text-xs text-slate-200"
          >
            <option value="ALL">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="border border-slate-700 bg-[#111827] px-3 py-2 text-xs text-slate-200"
          >
            <option value="ALL">All Categories</option>
            {categories.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>

          <ExportPrintToolbar
            exportLabel="Export Analytics"
            printLabel="Print Summary"
            onExport={(format) =>
              exportAnalyticsData(format, {
                totalEvents: events.length,
                alerts: filteredAlerts,
                trendData,
                categoryCounts: categoryBreakdown,
                severityCounts: sevCounts,
                topIps,
                filterSummary,
              })
            }
            onPrint={() => window.print()}
          />
        </div>
      </div>

      {/* Screen-Only Analytics Charts */}
      <div className="no-print space-y-6">
        <div className="border border-slate-800 bg-[#111827] p-5">
          <h2 className="mb-3 text-sm font-semibold text-slate-100">Event Volume &amp; Threat Detections Over Time</h2>
          <TrendChart data={trendData} height={240} />
        </div>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          <div className="border border-slate-800 bg-[#111827] p-5">
            <h2 className="mb-4 text-sm font-semibold text-slate-100">Attack Category Breakdown</h2>
            <HorizontalBarChart
              items={categoryBreakdown.map((c) => ({ label: c.category, value: c.count, accent: 'violet' as const }))}
            />
          </div>

          <div className="border border-slate-800 bg-[#111827] p-5">
            <h2 className="mb-4 text-sm font-semibold text-slate-100">Severity Distribution</h2>
            <HorizontalBarChart
              items={[
                { label: 'Critical', value: sevCounts.Critical, accent: 'red' },
                { label: 'High', value: sevCounts.High, accent: 'amber' },
                { label: 'Medium', value: sevCounts.Medium, accent: 'violet' },
                { label: 'Low', value: sevCounts.Low, accent: 'blue' },
              ]}
            />
          </div>

          <div className="border border-slate-800 bg-[#111827] p-5">
            <h2 className="mb-4 text-sm font-semibold text-slate-100">Top Suspicious Source IPs</h2>
            {topIps.length === 0 ? (
              <p className="text-xs text-slate-500">No suspicious IPs match the current filters.</p>
            ) : (
              <div className="divide-y divide-slate-800/70">
                {topIps.slice(0, 6).map((item) => (
                  <div key={item.ip} className="flex items-center justify-between py-2.5 text-xs">
                    <div>
                      <div className="font-mono text-slate-100 tabular-nums">{item.ip}</div>
                      <div className="text-[11px] text-slate-400">{item.count} alert(s)</div>
                    </div>
                    <div className="text-right">
                      <SeverityText severity={item.maxSeverity} />
                      <div className="font-mono text-[11px] text-slate-400 tabular-nums">{item.avgConf}% avg conf</div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Print-Only Analytics Executive Sheet */}
      <div className="print-only-sheet space-y-5">
        <PrintSheetHeader
          reportTitle="Security Analytics & Telemetry Summary"
          subtitle={`Applied Filters: ${filterSummary}`}
          metadata={[
            { label: 'Events Analyzed', value: String(events.length) },
            { label: 'Matching Alerts', value: String(filteredAlerts.length) },
            { label: 'Critical / High', value: `${sevCounts.Critical} / ${sevCounts.High}` },
            { label: 'Medium / Low', value: `${sevCounts.Medium} / ${sevCounts.Low}` },
          ]}
        />

        <div className="grid grid-cols-2 gap-4 print-break-inside-avoid">
          <div>
            <h2 className="mb-2 text-xs font-bold uppercase">Attack Category Breakdown</h2>
            <table className="w-full border-collapse border border-slate-300 text-[11px]">
              <thead>
                <tr className="bg-slate-100 text-left">
                  <th className="border border-slate-300 px-2.5 py-1.5">Category</th>
                  <th className="border border-slate-300 px-2.5 py-1.5 text-right">Detections</th>
                </tr>
              </thead>
              <tbody>
                {categoryBreakdown.map((c) => (
                  <tr key={c.category}>
                    <td className="border border-slate-300 px-2.5 py-1.5">{c.category}</td>
                    <td className="border border-slate-300 px-2.5 py-1.5 text-right font-mono">{c.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div>
            <h2 className="mb-2 text-xs font-bold uppercase">Top Suspicious Source IPs</h2>
            <table className="w-full border-collapse border border-slate-300 text-[11px]">
              <thead>
                <tr className="bg-slate-100 text-left">
                  <th className="border border-slate-300 px-2.5 py-1.5">IP Address</th>
                  <th className="border border-slate-300 px-2.5 py-1.5">Severity</th>
                  <th className="border border-slate-300 px-2.5 py-1.5 text-right">Avg Conf</th>
                </tr>
              </thead>
              <tbody>
                {topIps.slice(0, 8).map((ip) => (
                  <tr key={ip.ip}>
                    <td className="border border-slate-300 px-2.5 py-1.5 font-mono">{ip.ip}</td>
                    <td className="border border-slate-300 px-2.5 py-1.5">{ip.maxSeverity}</td>
                    <td className="border border-slate-300 px-2.5 py-1.5 text-right font-mono">{ip.avgConf}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="print-break-inside-avoid">
          <h2 className="mb-2 text-xs font-bold uppercase">Hourly Event &amp; Threat Trend</h2>
          <table className="w-full border-collapse border border-slate-300 text-[11px]">
            <thead>
              <tr className="bg-slate-100 text-left">
                <th className="border border-slate-300 px-2.5 py-1.5">UTC Bucket</th>
                <th className="border border-slate-300 px-2.5 py-1.5 text-right">Log Events</th>
                <th className="border border-slate-300 px-2.5 py-1.5 text-right">Threat Detections</th>
              </tr>
            </thead>
            <tbody>
              {trendData.map((t) => (
                <tr key={t.bucket}>
                  <td className="border border-slate-300 px-2.5 py-1.5 font-mono">{t.bucket}</td>
                  <td className="border border-slate-300 px-2.5 py-1.5 text-right font-mono">{t.events}</td>
                  <td className="border border-slate-300 px-2.5 py-1.5 text-right font-mono">{t.threats}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
