import React, { useEffect, useState } from 'react';
import { FileText, Search, Upload } from 'lucide-react';
import { formatUtcTime } from '../components/SeverityText';
import { ApiError, api } from '../lib/api';
import type { DatasetUploadRecord, DatasetValidationError, SecurityEvent } from '../shared/types';

interface LogAnalyzerViewProps {
  onAnalyzed: () => void;
  onNavigateAlerts: () => void;
}

export const LogAnalyzerView: React.FC<LogAnalyzerViewProps> = ({ onAnalyzed, onNavigateAlerts }) => {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [totalEventsCount, setTotalEventsCount] = useState(0);
  const [uploads, setUploads] = useState<DatasetUploadRecord[]>([]);
  const [samples, setSamples] = useState<
    Array<{ key: string; name: string; filename: string; format: 'csv' | 'json' | 'txt'; description: string }>
  >([]);
  const [query, setQuery] = useState('');
  const [actionFilter, setActionFilter] = useState('ALL');
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [feedbackMsg, setFeedbackMsg] = useState<{
    type: 'success' | 'error';
    text: string;
    validationErrors?: DatasetValidationError[];
  } | null>(null);
  const [expandedUploadId, setExpandedUploadId] = useState<string | null>(null);
  const [pasteMode, setPasteMode] = useState(false);
  const [manualFilename, setManualFilename] = useState('custom_security_logs.csv');
  const [manualContent, setManualContent] = useState('');
  const [manualFormat, setManualFormat] = useState<'csv' | 'json' | 'txt'>('csv');

  const fetchLogs = async (q = query, act = actionFilter) => {
    setLoading(true);
    try {
      const res = await api.getLogs({ q, action: act });
      setEvents(res.events);
      setTotalEventsCount(res.totalCount);
      setUploads(res.uploads);
      setSamples(res.samples);
    } catch (err) {
      setFeedbackMsg({ type: 'error', text: err instanceof Error ? err.message : 'Failed to load logs' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void fetchLogs('', 'ALL');
  }, []);

  const buildSuccessMessage = (res: {
    upload: DatasetUploadRecord;
    newEventsCount: number;
    newAlertsCount: number;
    replacedExisting?: boolean;
  }) => {
    const actionVerb = res.replacedExisting
      ? `Re-analyzed & replaced prior import of "${res.upload.filename}" (import #${res.upload.importCount ?? 1}, zero duplicate records)`
      : `Ingested "${res.upload.filename}"`;
    const invalidNote =
      res.upload.invalidCount > 0
        ? `, ${res.upload.invalidCount} invalid row(s) excluded from analysis`
        : '';
    return `${actionVerb}: ${res.newEventsCount} valid event(s) processed${invalidNote}, ${res.newAlertsCount} threat alert(s) detected.`;
  };

  const handleFileUpload = async (file: File) => {
    setUploading(true);
    setFeedbackMsg(null);
    try {
      const content = await file.text();
      const res = await api.uploadLogs({ filename: file.name, content });
      setFeedbackMsg({
        type: 'success',
        text: buildSuccessMessage(res),
        validationErrors: res.upload.validationErrors,
      });
      await fetchLogs(query, actionFilter);
      onAnalyzed();
    } catch (err) {
      if (err instanceof ApiError && err.upload) {
        await fetchLogs(query, actionFilter);
        setFeedbackMsg({
          type: 'error',
          text: `Ingestion rejected for "${err.upload.filename}": ${err.message} (${err.upload.invalidCount} invalid row(s), 0 valid events).`,
          validationErrors: err.upload.validationErrors,
        });
      } else {
        setFeedbackMsg({
          type: 'error',
          text: err instanceof Error ? err.message : 'File validation or analysis failed.',
        });
      }
    } finally {
      setUploading(false);
    }
  };

  const handleSampleLoad = async (sampleKey: string) => {
    setUploading(true);
    setFeedbackMsg(null);
    try {
      const res = await api.loadSampleLogs(sampleKey);
      setFeedbackMsg({
        type: 'success',
        text: buildSuccessMessage(res),
        validationErrors: res.upload.validationErrors,
      });
      await fetchLogs(query, actionFilter);
      onAnalyzed();
    } catch (err) {
      setFeedbackMsg({ type: 'error', text: err instanceof Error ? err.message : 'Failed to load sample dataset' });
    } finally {
      setUploading(false);
    }
  };

  const handlePasteSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setUploading(true);
    setFeedbackMsg(null);
    try {
      const res = await api.uploadLogs({
        filename: manualFilename || `manual.${manualFormat}`,
        content: manualContent,
        format: manualFormat,
      });
      setFeedbackMsg({
        type: 'success',
        text: buildSuccessMessage(res),
        validationErrors: res.upload.validationErrors,
      });
      setManualContent('');
      setPasteMode(false);
      await fetchLogs(query, actionFilter);
      onAnalyzed();
    } catch (err) {
      if (err instanceof ApiError && err.upload) {
        await fetchLogs(query, actionFilter);
        setFeedbackMsg({
          type: 'error',
          text: `Validation failed for "${err.upload.filename}": ${err.message} (${err.upload.invalidCount} invalid row(s)).`,
          validationErrors: err.upload.validationErrors,
        });
      } else {
        setFeedbackMsg({ type: 'error', text: err instanceof Error ? err.message : 'Validation failed.' });
      }
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-slate-100">Log Analyzer &amp; Dataset Ingestion</h1>
          <p className="mt-1 text-xs text-slate-400">
            Upload CSV, JSON, or TXT syslog files for schema validation, feature extraction, and hybrid ML + rule threat analysis.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setPasteMode(!pasteMode)}
          className="border border-slate-700 bg-[#111827] px-3.5 py-2 text-xs font-medium text-slate-200 hover:bg-slate-800"
        >
          {pasteMode ? 'Hide Raw Paste Input' : 'Paste Raw Logs'}
        </button>
      </div>

      {feedbackMsg && (
        <div
          className={`space-y-2 border p-4 text-xs ${
            feedbackMsg.type === 'success'
              ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200'
              : 'border-red-500/40 bg-red-500/10 text-red-200'
          }`}
        >
          <div className="flex flex-wrap items-center justify-between gap-3">
            <span>{feedbackMsg.text}</span>
            {feedbackMsg.type === 'success' && (
              <button
                type="button"
                onClick={onNavigateAlerts}
                className="bg-blue-600 px-3 py-1.5 font-medium text-white hover:bg-blue-500"
              >
                View Alerts
              </button>
            )}
          </div>
          {feedbackMsg.validationErrors && feedbackMsg.validationErrors.length > 0 && (
            <div className="border-t border-slate-700/60 pt-2">
              <div className="mb-1 text-[11px] font-medium text-amber-300">
                Excluded Malformed / Incomplete Rows ({feedbackMsg.validationErrors.length} shown):
              </div>
              <ul className="space-y-1 font-mono text-[11px] text-slate-300">
                {feedbackMsg.validationErrors.slice(0, 6).map((errItem, idx) => (
                  <li key={`${errItem.line}-${idx}`} className="truncate">
                    Line {errItem.line}: {errItem.reason}
                    {errItem.raw ? ` — ${errItem.raw}` : ''}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Upload Dropzone & Sample Datasets */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div
          onDragOver={(e) => e.preventDefault()}
          onDrop={(e) => {
            e.preventDefault();
            const f = e.dataTransfer.files[0];
            if (f) void handleFileUpload(f);
          }}
          className="flex flex-col justify-between border border-dashed border-slate-700 bg-[#111827] p-6"
        >
          <div>
            <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
              <Upload className="h-4 w-4 text-blue-400" />
              <span>Upload Security Log File</span>
            </div>
            <p className="mt-2 text-xs leading-relaxed text-slate-400">
              Supports <span className="font-mono text-slate-300">.csv</span> (SIEM/auth table),{' '}
              <span className="font-mono text-slate-300">.json</span> (array of event objects), and{' '}
              <span className="font-mono text-slate-300">.txt</span> (raw sshd/syslog lines). Malformed lines are validated and excluded from normalized records and ML analysis.
            </p>
          </div>

          <div className="mt-5 flex flex-wrap items-center gap-3">
            <label className="cursor-pointer bg-blue-600 px-4 py-2 text-xs font-medium text-white hover:bg-blue-500">
              <span>{uploading ? 'Analyzing...' : 'Select File to Analyze'}</span>
              <input
                type="file"
                accept=".csv,.json,.txt,.log"
                disabled={uploading}
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) void handleFileUpload(file);
                  e.target.value = '';
                }}
                className="hidden"
              />
            </label>
            <span className="text-xs text-slate-500">or drag and drop a file here (max 2 MB)</span>
          </div>
        </div>

        <div className="border border-slate-800 bg-[#111827] p-5">
          <h2 className="text-sm font-semibold text-slate-100">Sample Demonstration Datasets</h2>
          <p className="mt-0.5 text-xs text-slate-400">Reproducible synthetic logs for testing parsers and detectors</p>
          <div className="mt-3 divide-y divide-slate-800/80">
            {samples.map((s) => (
              <div key={s.key} className="flex items-center justify-between gap-3 py-2.5">
                <div className="min-w-0">
                  <div className="truncate text-xs font-medium text-slate-200">{s.name}</div>
                  <div className="truncate text-[11px] text-slate-400">{s.description}</div>
                </div>
                <button
                  type="button"
                  disabled={uploading}
                  onClick={() => void handleSampleLoad(s.key)}
                  className="shrink-0 border border-slate-700 px-3 py-1.5 text-xs font-medium text-blue-400 hover:bg-slate-800 disabled:opacity-50"
                >
                  Load &amp; Analyze
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>

      {pasteMode && (
        <form onSubmit={handlePasteSubmit} className="border border-slate-800 bg-[#111827] p-5 space-y-3">
          <div className="flex flex-wrap items-center gap-3">
            <div>
              <label className="block text-xs text-slate-400">Batch Name</label>
              <input
                type="text"
                value={manualFilename}
                onChange={(e) => setManualFilename(e.target.value)}
                className="mt-1 border border-slate-700 bg-[#060913] px-3 py-1.5 font-mono text-xs text-slate-100"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400">Format</label>
              <select
                value={manualFormat}
                onChange={(e) => setManualFormat(e.target.value as 'csv' | 'json' | 'txt')}
                className="mt-1 border border-slate-700 bg-[#060913] px-3 py-1.5 text-xs text-slate-100"
              >
                <option value="csv">CSV</option>
                <option value="json">JSON</option>
                <option value="txt">TXT (Syslog)</option>
              </select>
            </div>
          </div>
          <textarea
            rows={5}
            required
            value={manualContent}
            onChange={(e) => setManualContent(e.target.value)}
            placeholder="Paste CSV rows, JSON array, or syslog lines..."
            className="w-full border border-slate-700 bg-[#060913] p-3 font-mono text-xs text-slate-100 focus:border-blue-500 focus:outline-none"
          />
          <div className="flex justify-end">
            <button
              type="submit"
              disabled={uploading}
              className="bg-blue-600 px-4 py-2 text-xs font-medium text-white hover:bg-blue-500 disabled:opacity-50"
            >
              Validate &amp; Run Detection
            </button>
          </div>
        </form>
      )}

      {/* Upload Validation History */}
      {uploads.length > 0 && (
        <div className="border border-slate-800 bg-[#111827] p-5">
          <h2 className="mb-3 text-sm font-semibold text-slate-100">Dataset Upload &amp; Validation History</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800 text-slate-400">
                <tr>
                  <th className="py-2 pr-3 font-medium">Dataset File</th>
                  <th className="py-2 pr-3 font-medium">Format</th>
                  <th className="py-2 pr-3 font-medium text-right">Valid Rows</th>
                  <th className="py-2 pr-3 font-medium text-right">Invalid Rows</th>
                  <th className="py-2 pr-3 font-medium text-right">Threats Flagged</th>
                  <th className="py-2 font-medium text-right">Ingested At</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {uploads.slice(0, 10).map((u) => (
                  <React.Fragment key={u.id}>
                    <tr>
                      <td className="py-2 pr-3 font-medium text-slate-200">
                        <span>{u.filename}</span>
                        {u.replacedPrevious && (
                          <span className="ml-2 font-mono text-[11px] font-normal text-blue-400">
                            (import #{u.importCount ?? 2}, replaced prior)
                          </span>
                        )}
                      </td>
                      <td className="py-2 pr-3 font-mono uppercase text-slate-400">{u.format}</td>
                      <td className="py-2 pr-3 text-right font-mono text-emerald-400 tabular-nums">{u.validCount}</td>
                      <td className="py-2 pr-3 text-right font-mono text-amber-400 tabular-nums">
                        <span>{u.invalidCount}</span>
                        {u.invalidCount > 0 && u.validationErrors.length > 0 && (
                          <button
                            type="button"
                            onClick={() => setExpandedUploadId(expandedUploadId === u.id ? null : u.id)}
                            className="ml-2 text-[11px] font-sans text-blue-400 hover:underline"
                          >
                            {expandedUploadId === u.id ? 'hide' : 'details'}
                          </button>
                        )}
                      </td>
                      <td className="py-2 pr-3 text-right font-mono text-violet-300 tabular-nums">{u.threatsDetected}</td>
                      <td className="py-2 text-right font-mono text-slate-400 tabular-nums">{formatUtcTime(u.uploadedAt)}</td>
                    </tr>
                    {expandedUploadId === u.id && u.validationErrors.length > 0 && (
                      <tr className="bg-[#060913]">
                        <td colSpan={6} className="px-3 py-2.5 font-mono text-[11px] text-amber-200">
                          <div className="mb-1 text-slate-400">Validation errors excluded from analysis:</div>
                          <ul className="space-y-0.5">
                            {u.validationErrors.map((errItem, idx) => (
                              <li key={`${u.id}-err-${idx}`} className="truncate">
                                Line {errItem.line}: {errItem.reason}
                                {errItem.raw ? ` — ${errItem.raw}` : ''}
                              </li>
                            ))}
                          </ul>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Searchable Log Records Table */}
      <div className="border border-slate-800 bg-[#111827] p-5">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">Parsed Security Log Records</h2>
            <p className="text-xs text-slate-400">
              Showing {events.length} of {totalEventsCount} normalized log entries
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-500" />
              <input
                type="text"
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  void fetchLogs(e.target.value, actionFilter);
                }}
                placeholder="Search IP, user, message..."
                className="w-60 border border-slate-700 bg-[#060913] py-1.5 pl-8 pr-3 text-xs text-slate-100 focus:border-blue-500 focus:outline-none"
              />
            </div>
            <select
              value={actionFilter}
              onChange={(e) => {
                setActionFilter(e.target.value);
                void fetchLogs(query, e.target.value);
              }}
              className="border border-slate-700 bg-[#060913] px-3 py-1.5 text-xs text-slate-200"
            >
              <option value="ALL">All Actions</option>
              <option value="ALLOW">ALLOW</option>
              <option value="FAILED">FAILED</option>
              <option value="DENIED">DENIED</option>
              <option value="BLOCKED">BLOCKED</option>
            </select>
          </div>
        </div>

        {loading ? (
          <div className="space-y-2">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-9 animate-pulse bg-slate-800/50" />
            ))}
          </div>
        ) : events.length === 0 ? (
          <div className="py-10 text-center text-sm text-slate-500">
            <FileText className="mx-auto mb-2 h-6 w-6 text-slate-600" />
            No log records match your search filter.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800 text-slate-400">
                <tr>
                  <th className="py-2 pr-3 font-medium">Timestamp</th>
                  <th className="py-2 pr-3 font-medium">Source IP</th>
                  <th className="py-2 pr-3 font-medium">Dest / Port</th>
                  <th className="py-2 pr-3 font-medium">User</th>
                  <th className="py-2 pr-3 font-medium">Action</th>
                  <th className="py-2 pr-3 font-medium">Message</th>
                  <th className="py-2 font-medium text-right">Z-Score</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {events.slice(0, 80).map((ev) => (
                  <tr key={ev.id} className="hover:bg-slate-800/30">
                    <td className="py-2 pr-3 font-mono text-slate-400 whitespace-nowrap tabular-nums">
                      {formatUtcTime(ev.timestamp)}
                    </td>
                    <td className="py-2 pr-3 font-mono text-slate-200 tabular-nums">{ev.sourceIp}</td>
                    <td className="py-2 pr-3 font-mono text-slate-300 tabular-nums">
                      {ev.destinationIp}:{ev.destinationPort}
                    </td>
                    <td className="py-2 pr-3 font-mono text-slate-300">{ev.username}</td>
                    <td className="py-2 pr-3">
                      <span
                        className={`font-mono text-[11px] font-medium ${
                          ev.action === 'ALLOW' ? 'text-emerald-400' : 'text-red-400'
                        }`}
                      >
                        {ev.action}
                      </span>
                    </td>
                    <td className="max-w-md truncate py-2 pr-3 text-slate-300" title={ev.message}>
                      {ev.message}
                    </td>
                    <td className="py-2 text-right font-mono text-slate-300 tabular-nums">
                      {ev.features.interArrivalZScore.toFixed(2)}
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
