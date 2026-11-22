import React from 'react';
import type { AlertStatus, Severity } from '../shared/types';

export const SeverityText: React.FC<{ severity: Severity }> = ({ severity }) => {
  const colorMap: Record<Severity, string> = {
    Critical: 'text-red-400',
    High: 'text-orange-400',
    Medium: 'text-amber-400',
    Low: 'text-blue-400',
  };
  const symbolMap: Record<Severity, string> = {
    Critical: '◆',
    High: '▲',
    Medium: '■',
    Low: '●',
  };
  return (
    <span className={`inline-flex items-center gap-1.5 font-mono text-xs font-medium whitespace-nowrap ${colorMap[severity]}`}>
      <span aria-hidden="true" className="text-[10px] leading-none">
        {symbolMap[severity]}
      </span>
      <span>{severity}</span>
    </span>
  );
};

export const AlertStatusText: React.FC<{ status: AlertStatus }> = ({ status }) => {
  const styles: Record<AlertStatus, { text: string; label: string }> = {
    open: { text: 'text-red-300', label: 'Open' },
    acknowledged: { text: 'text-amber-300', label: 'Acknowledged' },
    resolved: { text: 'text-emerald-400', label: 'Resolved' },
  };
  const cfg = styles[status];
  return <span className={`text-xs font-medium whitespace-nowrap ${cfg.text}`}>{cfg.label}</span>;
};

export function formatUtcTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}
