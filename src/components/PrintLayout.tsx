import React from 'react';

interface PrintSheetHeaderProps {
  reportTitle: string;
  subtitle: string;
  metadata?: Array<{ label: string; value: string }>;
}

export const PrintSheetHeader: React.FC<PrintSheetHeaderProps> = ({ reportTitle, subtitle, metadata = [] }) => {
  const generatedUtc = new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
  return (
    <div className="mb-5 border-b-2 border-slate-900 pb-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="text-base font-bold tracking-wide text-slate-950">SENTINELFORGE</div>
          <div className="text-[11px] text-slate-600">AI-Powered Threat Detection and Security Analytics Platform</div>
        </div>
        <div className="text-right font-mono text-[10px] text-slate-700">
          <div>Generated: {generatedUtc}</div>
          <div>Classification: Defensive SOC Record</div>
        </div>
      </div>

      <h1 className="mt-4 text-lg font-bold text-slate-950">{reportTitle}</h1>
      <p className="mt-0.5 text-xs text-slate-700">{subtitle}</p>

      {metadata.length > 0 && (
        <div className="mt-3 grid grid-cols-2 gap-2 border border-slate-300 bg-slate-50 p-2.5 text-[11px] sm:grid-cols-4">
          {metadata.map((m) => (
            <div key={m.label}>
              <div className="text-[10px] font-medium uppercase text-slate-500">{m.label}</div>
              <div className="font-mono font-semibold text-slate-900">{m.value}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
