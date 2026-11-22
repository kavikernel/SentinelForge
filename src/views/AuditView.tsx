import React, { useEffect, useState } from 'react';
import { formatUtcTime } from '../components/SeverityText';
import { api } from '../lib/api';
import type { AuditLogEntry } from '../shared/types';

export const AuditView: React.FC = () => {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [actionFilter, setActionFilter] = useState('ALL');
  const [loading, setLoading] = useState(true);

  const load = async (act = actionFilter) => {
    setLoading(true);
    try {
      const res = await api.getAuditLogs(act);
      setLogs(res.auditLogs);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load('ALL');
  }, []);

  const uniqueActions = Array.from(new Set(logs.map((l) => l.action)));

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-slate-100">Immutable SOC Audit Trail</h1>
          <p className="mt-1 text-xs text-slate-400">
            Tracks every incident acknowledgment, resolution, feedback label, forensic note, ML retrain, and administrative change.
          </p>
        </div>

        <select
          value={actionFilter}
          onChange={(e) => {
            setActionFilter(e.target.value);
            void load(e.target.value);
          }}
          className="border border-slate-700 bg-[#111827] px-3 py-2 text-xs text-slate-200"
        >
          <option value="ALL">All Actions</option>
          {uniqueActions.map((a) => (
            <option key={a} value={a}>
              {a}
            </option>
          ))}
        </select>
      </div>

      <div className="border border-slate-800 bg-[#111827] p-5">
        {loading ? (
          <div className="h-48 animate-pulse bg-slate-800/40" />
        ) : logs.length === 0 ? (
          <p className="py-8 text-center text-sm text-slate-500">No audit entries recorded yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800 text-slate-400">
                <tr>
                  <th className="py-2 pr-3 font-medium">Timestamp</th>
                  <th className="py-2 pr-3 font-medium">Actor</th>
                  <th className="py-2 pr-3 font-medium">Role</th>
                  <th className="py-2 pr-3 font-medium">Action</th>
                  <th className="py-2 pr-3 font-medium">Target</th>
                  <th className="py-2 font-medium">Summary</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {logs.map((entry) => (
                  <tr key={entry.id} className="hover:bg-slate-800/30">
                    <td className="py-2.5 pr-3 font-mono text-slate-400 whitespace-nowrap tabular-nums">
                      {formatUtcTime(entry.timestamp)}
                    </td>
                    <td className="py-2.5 pr-3 font-mono text-slate-200">{entry.actorUsername}</td>
                    <td className="py-2.5 pr-3 font-mono text-violet-300">{entry.actorRole}</td>
                    <td className="py-2.5 pr-3 font-mono text-blue-300">{entry.action}</td>
                    <td className="py-2.5 pr-3 font-mono text-slate-400">{entry.entityId}</td>
                    <td className="py-2.5 text-slate-300">
                      {entry.summary}
                      {entry.previousValue && entry.newValue && (
                        <span className="ml-2 font-mono text-[11px] text-slate-400">
                          ({entry.previousValue} → {entry.newValue})
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
