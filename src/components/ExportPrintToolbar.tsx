import React, { useEffect, useRef, useState } from 'react';
import { ChevronDown, Download, Printer } from 'lucide-react';
import type { ExportFormat } from '../lib/exporters';

interface ExportPrintToolbarProps {
  onExport: (format: ExportFormat) => Promise<string> | string;
  onPrint?: () => void;
  exportLabel?: string;
  printLabel?: string;
  disabled?: boolean;
}

export const ExportPrintToolbar: React.FC<ExportPrintToolbarProps> = ({
  onExport,
  onPrint,
  exportLabel = 'Export',
  printLabel = 'Print',
  disabled = false,
}) => {
  const [menuOpen, setMenuOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onDocClick = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setMenuOpen(false);
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setMenuOpen(false);
    };
    document.addEventListener('mousedown', onDocClick);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDocClick);
      document.removeEventListener('keydown', onKey);
    };
  }, []);

  const handleSelect = async (format: ExportFormat) => {
    setMenuOpen(false);
    setBusy(true);
    setFeedback(null);
    try {
      const msg = await onExport(format);
      setFeedback({ type: 'success', text: msg });
    } catch (err) {
      setFeedback({
        type: 'error',
        text: err instanceof Error ? err.message : `Failed to export ${format.toUpperCase()} report.`,
      });
    } finally {
      setBusy(false);
    }
  };

  const handlePrintClick = () => {
    if (!onPrint) return;
    setFeedback(null);
    try {
      onPrint();
      setFeedback({ type: 'success', text: 'Print dialog opened with SentinelForge report layout.' });
    } catch (err) {
      setFeedback({
        type: 'error',
        text: err instanceof Error ? err.message : 'Unable to open print preview.',
      });
    }
  };

  return (
    <div ref={containerRef} className="no-print flex flex-col items-end gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative">
          <button
            type="button"
            disabled={disabled || busy}
            aria-haspopup="menu"
            aria-expanded={menuOpen}
            onClick={() => setMenuOpen((prev) => !prev)}
            className="inline-flex items-center gap-1.5 border border-slate-700 bg-[#111827] px-3.5 py-2 text-xs font-medium text-slate-200 hover:border-blue-500/60 hover:bg-slate-800 disabled:opacity-50 whitespace-nowrap shrink-0"
          >
            <Download className="h-3.5 w-3.5 text-blue-400" />
            <span>{busy ? 'Exporting...' : exportLabel}</span>
            <ChevronDown className="h-3.5 w-3.5 text-slate-400" />
          </button>

          {menuOpen && (
            <div
              role="menu"
              className="absolute right-0 z-30 mt-1 w-44 border border-slate-700 bg-[#0B1120] py-1 shadow-lg"
            >
              <button
                type="button"
                role="menuitem"
                onClick={() => void handleSelect('csv')}
                className="flex w-full items-center justify-between px-3.5 py-2 text-left text-xs text-slate-200 hover:bg-slate-800"
              >
                <span>Export CSV</span>
                <span className="font-mono text-[10px] text-slate-400">.csv</span>
              </button>
              <button
                type="button"
                role="menuitem"
                onClick={() => void handleSelect('json')}
                className="flex w-full items-center justify-between px-3.5 py-2 text-left text-xs text-slate-200 hover:bg-slate-800"
              >
                <span>Export JSON</span>
                <span className="font-mono text-[10px] text-slate-400">.json</span>
              </button>
              <button
                type="button"
                role="menuitem"
                onClick={() => void handleSelect('pdf')}
                className="flex w-full items-center justify-between px-3.5 py-2 text-left text-xs text-slate-200 hover:bg-slate-800"
              >
                <span>Generate PDF Report</span>
                <span className="font-mono text-[10px] text-violet-300">.pdf</span>
              </button>
            </div>
          )}
        </div>

        {onPrint && (
          <button
            type="button"
            disabled={disabled}
            onClick={handlePrintClick}
            className="inline-flex items-center gap-1.5 border border-slate-700 bg-[#111827] px-3.5 py-2 text-xs font-medium text-slate-200 hover:border-blue-500/60 hover:bg-slate-800 disabled:opacity-50 whitespace-nowrap shrink-0"
          >
            <Printer className="h-3.5 w-3.5 text-slate-300" />
            <span>{printLabel}</span>
          </button>
        )}
      </div>

      {feedback && (
        <div
          role="status"
          className={`flex items-center gap-3 border px-3 py-1.5 text-xs ${
            feedback.type === 'success'
              ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200'
              : 'border-red-500/40 bg-red-500/10 text-red-200'
          }`}
        >
          <span>{feedback.text}</span>
          <button
            type="button"
            onClick={() => setFeedback(null)}
            className="text-[11px] underline opacity-80 hover:opacity-100"
          >
            Dismiss
          </button>
        </div>
      )}
    </div>
  );
};
