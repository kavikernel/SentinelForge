import React, { useEffect, useState } from 'react';
import { GitBranch } from 'lucide-react';
import { SeverityText, formatUtcTime } from '../components/SeverityText';
import { api } from '../lib/api';
import type { AttackSequence, SecurityEvent } from '../shared/types';

interface CorrelationViewProps {
  onSelectAlert: (alertId: string) => void;
}

export const CorrelationView: React.FC<CorrelationViewProps> = ({ onSelectAlert }) => {
  const [sequences, setSequences] = useState<AttackSequence[]>([]);
  const [timelineEvents, setTimelineEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        const [seqRes, logRes] = await Promise.all([api.getCorrelations(), api.getLogs()]);
        setSequences(seqRes.sequences);
        setTimelineEvents(
          [...logRes.events]
            .sort((a, b) => b.timestamp.localeCompare(a.timestamp))
            .slice(0, 24)
        );
      } finally {
        setLoading(false);
      }
    };
    void load();
  }, []);

  if (loading) {
    return <div className="h-64 animate-pulse border border-slate-800 bg-[#111827]" />;
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-slate-100">
          Attack Correlation &amp; Security Event Timeline
        </h1>
        <p className="mt-1 text-xs text-slate-400">
          Groups related detections sharing source IPs into ordered multi-stage attack sequences mapped across MITRE ATT&amp;CK tactics.
        </p>
      </div>

      {sequences.length === 0 ? (
        <div className="border border-slate-800 bg-[#111827] p-8 text-center text-sm text-slate-400">
          <GitBranch className="mx-auto mb-2 h-6 w-6 text-slate-600" />
          No multi-stage attack sequences correlated yet. Upload or load multi-stage log samples to observe kill-chain grouping.
        </div>
      ) : (
        <div className="space-y-4">
          {sequences.map((seq) => (
            <div key={seq.id} className="border border-slate-800 bg-[#111827] p-5">
              <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-800 pb-4">
                <div>
                  <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
                    <SeverityText severity={seq.overallSeverity} />
                    <span>·</span>
                    <span className="font-mono text-slate-200">{seq.sourceIp}</span>
                    <span>·</span>
                    <span className="font-mono">{seq.stageCount} correlated stages</span>
                    <span>·</span>
                    <span>{seq.isDemoData ? 'Synthetic Demo Sequence' : 'Analyzed Log Sequence'}</span>
                  </div>
                  <p className="mt-2 text-sm font-medium text-slate-100">{seq.narrative}</p>
                  <div className="mt-1 font-mono text-[11px] text-slate-400 tabular-nums">
                    Window: {formatUtcTime(seq.startTime)} to {formatUtcTime(seq.endTime)} · Targets: {seq.targetUsers.join(', ')}
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-[11px] text-slate-400">Sequence Risk Score</div>
                  <div className="font-mono text-2xl font-semibold text-violet-300 tabular-nums">{seq.riskScore}/100</div>
                </div>
              </div>

              {/* Ordered Kill-Chain Stages */}
              <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-4">
                {seq.stages.map((st) => (
                  <button
                    key={`${seq.id}-${st.order}`}
                    type="button"
                    onClick={() => onSelectAlert(st.alertId)}
                    className="flex flex-col justify-between border border-slate-800 bg-[#060913] p-3.5 text-left transition-colors hover:border-blue-500/60"
                  >
                    <div>
                      <div className="flex items-center justify-between text-[11px] text-slate-400">
                        <span className="font-mono text-blue-400">Stage 0{st.order}</span>
                        <SeverityText severity={st.severity} />
                      </div>
                      <div className="mt-1.5 text-xs font-semibold text-slate-100">{st.category}</div>
                      <div className="mt-1 font-mono text-[11px] text-violet-300">{st.mitreTactic}</div>
                      <div className="font-mono text-[11px] text-slate-400">{st.mitreTechnique}</div>
                    </div>
                    <div className="mt-3 border-t border-slate-800/80 pt-2 font-mono text-[11px] text-slate-500 tabular-nums">
                      {formatUtcTime(st.timestamp)}
                    </div>
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Chronological Event Timeline */}
      <div className="border border-slate-800 bg-[#111827] p-5">
        <h2 className="text-sm font-semibold text-slate-100">Chronological Security Event Timeline</h2>
        <p className="mt-0.5 text-xs text-slate-400">Most recent 24 ingested security events ordered chronologically</p>
        <div className="mt-4 divide-y divide-slate-800/70">
          {timelineEvents.map((ev) => (
            <div key={ev.id} className="grid grid-cols-1 gap-2 py-2.5 text-xs md:grid-cols-12 md:items-center">
              <div className="font-mono text-slate-400 tabular-nums md:col-span-3">{formatUtcTime(ev.timestamp)}</div>
              <div className="font-mono text-slate-200 tabular-nums md:col-span-2">{ev.sourceIp}</div>
              <div className="font-mono text-slate-300 md:col-span-2">
                {ev.eventType} · {ev.action}
              </div>
              <div className="truncate text-slate-300 md:col-span-4" title={ev.message}>
                {ev.message}
              </div>
              <div className="text-right font-mono text-slate-400 tabular-nums md:col-span-1">
                :{ev.destinationPort}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
