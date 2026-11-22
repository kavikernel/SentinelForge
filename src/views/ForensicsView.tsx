import React, { useEffect, useState } from 'react';
import { FileSearch, Send } from 'lucide-react';
import { ExportPrintToolbar } from '../components/ExportPrintToolbar';
import { PrintSheetHeader } from '../components/PrintLayout';
import { SeverityText, formatUtcTime } from '../components/SeverityText';
import { api } from '../lib/api';
import { exportForensicCaseData } from '../lib/exporters';
import type { ForensicCase } from '../shared/types';

interface ForensicsViewProps {
  initialCaseId?: string | null;
  onChanged: () => void;
}

export const ForensicsView: React.FC<ForensicsViewProps> = ({ initialCaseId, onChanged }) => {
  const [cases, setCases] = useState<ForensicCase[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(initialCaseId ?? null);
  const [noteInput, setNoteInput] = useState('');
  const [statusInput, setStatusInput] = useState<'investigating' | 'contained' | 'closed'>('investigating');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  const loadCases = async () => {
    setLoading(true);
    try {
      const res = await api.getForensics();
      setCases(res.cases);
      if (initialCaseId && res.cases.some((c) => c.id === initialCaseId)) {
        setSelectedId(initialCaseId);
      } else if (!selectedId && res.cases.length > 0) {
        setSelectedId(res.cases[0].id);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadCases();
  }, [initialCaseId]);

  const selected = cases.find((c) => c.id === selectedId) ?? null;

  useEffect(() => {
    if (selected) setStatusInput(selected.status);
  }, [selected?.id]);

  const handleSaveNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selected) return;
    setSaving(true);
    try {
      const res = await api.addForensicNote(selected.id, noteInput, statusInput);
      setCases((prev) => prev.map((c) => (c.id === selected.id ? res.forensicCase : c)));
      setNoteInput('');
      onChanged();
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return <div className="h-64 animate-pulse border border-slate-800 bg-[#111827]" />;
  }

  return (
    <div className="space-y-6">
      <div className="no-print flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-slate-100">Digital Forensics &amp; Evidence Chain</h1>
          <p className="mt-1 text-xs text-slate-400">
            Preserve raw log artifacts with SHA-256 integrity digests, timeline reconstruction, and audited investigation notes.
          </p>
        </div>

        {selected && (
          <ExportPrintToolbar
            exportLabel="Export Record"
            printLabel="Print Record"
            onExport={(format) => exportForensicCaseData(format, selected)}
            onPrint={() => window.print()}
          />
        )}
      </div>

      {cases.length === 0 ? (
        <div className="border border-slate-800 bg-[#111827] p-8 text-center text-sm text-slate-400">
          <FileSearch className="mx-auto mb-2 h-6 w-6 text-slate-600" />
          No forensic cases opened yet. Escalate an incident from Alert Management to capture evidence.
        </div>
      ) : (
        <>
          {/* Screen-Only Forensics Split View */}
          <div className="no-print grid grid-cols-1 gap-6 xl:grid-cols-12">
            <div className="border border-slate-800 bg-[#111827] xl:col-span-4 divide-y divide-slate-800/80">
              {cases.map((fc) => (
                <button
                  key={fc.id}
                  type="button"
                  onClick={() => setSelectedId(fc.id)}
                  className={`w-full p-4 text-left transition-colors ${
                    fc.id === selected?.id ? 'bg-blue-600/15' : 'hover:bg-slate-800/40'
                  }`}
                >
                  <div className="flex items-center justify-between text-xs">
                    <SeverityText severity={fc.severity} />
                    <span className="font-mono uppercase text-slate-400">{fc.status}</span>
                  </div>
                  <div className="mt-1.5 text-xs font-semibold text-slate-100">{fc.title}</div>
                  <div className="mt-1 font-mono text-[11px] text-slate-400">
                    {fc.sourceIp} · {fc.notes.length} note(s)
                  </div>
                </button>
              ))}
            </div>

            <div className="border border-slate-800 bg-[#111827] p-6 xl:col-span-8">
              {!selected ? (
                <p className="text-sm text-slate-500">Select a forensic case to inspect evidence artifacts.</p>
              ) : (
                <div className="space-y-6">
                  <div className="border-b border-slate-800 pb-4">
                    <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-400">
                      <div className="flex items-center gap-2">
                        <SeverityText severity={selected.severity} />
                        <span>·</span>
                        <span className="font-mono">{selected.id}</span>
                        <span>·</span>
                        <span>{selected.isDemoData ? 'Synthetic Demo Case' : 'Active Incident Case'}</span>
                      </div>
                      <span className="font-mono uppercase text-blue-300">Status: {selected.status}</span>
                    </div>
                    <h2 className="mt-2 text-lg font-semibold text-slate-100">{selected.title}</h2>
                    <p className="mt-1 text-xs text-slate-300">{selected.evidenceSummary}</p>
                    <div className="mt-3 border border-slate-800 bg-[#060913] p-3 font-mono text-[11px] text-slate-300 break-all">
                      Evidence SHA-256: <span className="text-emerald-400">{selected.evidenceSha256}</span>
                    </div>
                  </div>

                  <div>
                    <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Preserved Raw Log Evidence</h3>
                    <pre className="mt-2 max-h-40 overflow-auto border border-slate-800 bg-[#060913] p-3 font-mono text-[11px] leading-relaxed text-slate-300">
                      {selected.rawArtifacts.join('\n') || 'No raw lines captured.'}
                    </pre>
                  </div>

                  <div>
                    <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Case Timeline</h3>
                    <div className="mt-2 divide-y divide-slate-800/70">
                      {selected.timeline.map((item, idx) => (
                        <div key={idx} className="flex flex-wrap items-center justify-between gap-2 py-2 text-xs">
                          <span className="text-slate-200">{item.event}</span>
                          <span className="font-mono text-[11px] text-slate-400 tabular-nums">
                            {item.actor} · {formatUtcTime(item.timestamp)}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <form onSubmit={handleSaveNote} className="border-t border-slate-800 pt-5 space-y-3">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <h3 className="text-sm font-semibold text-slate-100">Add Investigation Note / Update Containment</h3>
                      <select
                        value={statusInput}
                        onChange={(e) => setStatusInput(e.target.value as 'investigating' | 'contained' | 'closed')}
                        className="border border-slate-700 bg-[#060913] px-3 py-1.5 text-xs text-slate-200"
                      >
                        <option value="investigating">Investigating</option>
                        <option value="contained">Contained</option>
                        <option value="closed">Closed</option>
                      </select>
                    </div>
                    <textarea
                      rows={3}
                      value={noteInput}
                      onChange={(e) => setNoteInput(e.target.value)}
                      placeholder="Document forensic findings, IOC correlations, or containment verification..."
                      className="w-full border border-slate-700 bg-[#060913] p-3 text-xs text-slate-100 focus:border-blue-500 focus:outline-none"
                    />
                    <div className="flex justify-end">
                      <button
                        type="submit"
                        disabled={saving}
                        className="inline-flex items-center gap-1.5 bg-blue-600 px-4 py-2 text-xs font-medium text-white hover:bg-blue-500 disabled:opacity-50"
                      >
                        <Send className="h-3.5 w-3.5" />
                        <span>{saving ? 'Saving...' : 'Save Note & Update Case'}</span>
                      </button>
                    </div>
                  </form>

                  {selected.notes.length > 0 && (
                    <div className="space-y-2 border-t border-slate-800 pt-4">
                      <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Investigator Notes</h3>
                      {selected.notes.map((n) => (
                        <div key={n.id} className="border border-slate-800 bg-[#060913] p-3 text-xs">
                          <div className="flex justify-between text-[11px] text-slate-400">
                            <span className="font-medium text-slate-200">
                              {n.author} ({n.authorRole})
                            </span>
                            <span className="font-mono tabular-nums">{formatUtcTime(n.timestamp)}</span>
                          </div>
                          <p className="mt-1.5 text-slate-300">{n.content}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Print-Only Forensic Investigation Record */}
          {selected && (
            <div className="print-only-sheet space-y-5">
              <PrintSheetHeader
                reportTitle="Digital Forensics Investigation Record"
                subtitle={selected.title}
                metadata={[
                  { label: 'Case ID', value: selected.id },
                  { label: 'Severity', value: selected.severity },
                  { label: 'Status', value: selected.status.toUpperCase() },
                  { label: 'Source IP', value: selected.sourceIp },
                ]}
              />

              <div className="print-break-inside-avoid space-y-2 text-[11px]">
                <div><span className="font-bold">Alert Reference:</span> <span className="font-mono">{selected.alertId}</span></div>
                <div><span className="font-bold">Evidence Summary:</span> {selected.evidenceSummary}</div>
                <div className="border border-slate-300 bg-slate-50 p-2 font-mono text-[10px] break-all">
                  Chain-of-Custody SHA-256: {selected.evidenceSha256}
                </div>
              </div>

              <div className="print-break-inside-avoid">
                <h2 className="mb-1.5 text-xs font-bold uppercase">Preserved Raw Log Artifacts</h2>
                <pre className="border border-slate-300 bg-slate-50 p-2.5 font-mono text-[10px] whitespace-pre-wrap">
                  {selected.rawArtifacts.join('\n') || 'No raw lines captured.'}
                </pre>
              </div>

              <div className="print-break-inside-avoid">
                <h2 className="mb-1.5 text-xs font-bold uppercase">Chronological Case Timeline</h2>
                <table className="w-full border-collapse border border-slate-300 text-[11px]">
                  <thead>
                    <tr className="bg-slate-100 text-left">
                      <th className="border border-slate-300 px-2.5 py-1.5">Timestamp</th>
                      <th className="border border-slate-300 px-2.5 py-1.5">Actor</th>
                      <th className="border border-slate-300 px-2.5 py-1.5">Event</th>
                    </tr>
                  </thead>
                  <tbody>
                    {selected.timeline.map((item, idx) => (
                      <tr key={idx}>
                        <td className="border border-slate-300 px-2.5 py-1.5 font-mono">{formatUtcTime(item.timestamp)}</td>
                        <td className="border border-slate-300 px-2.5 py-1.5 font-mono">{item.actor}</td>
                        <td className="border border-slate-300 px-2.5 py-1.5">{item.event}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="print-break-inside-avoid">
                <h2 className="mb-1.5 text-xs font-bold uppercase">Investigator Notes ({selected.notes.length})</h2>
                {selected.notes.length === 0 ? (
                  <p className="text-[11px]">No investigator notes recorded.</p>
                ) : (
                  <div className="space-y-2">
                    {selected.notes.map((n) => (
                      <div key={n.id} className="border border-slate-300 p-2.5 text-[11px]">
                        <div className="font-semibold">
                          {n.author} ({n.authorRole}) · {formatUtcTime(n.timestamp)}
                        </div>
                        <div className="mt-1">{n.content}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
};
