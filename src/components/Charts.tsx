import React, { useState } from 'react';
import type { ConfusionMatrix } from '../shared/types';

export const TrendChart: React.FC<{
  data: Array<{ bucket: string; events: number; threats: number }>;
  height?: number;
}> = ({ data, height = 220 }) => {
  const [hoveredIdx, setHoveredIdx] = useState<number | null>(null);

  if (data.length === 0) {
    return (
      <div className="flex h-48 items-center justify-center text-sm text-slate-500">
        No time-series events available yet.
      </div>
    );
  }

  const width = 680;
  const padLeft = 36;
  const padRight = 16;
  const padTop = 18;
  const padBottom = 34;
  const innerW = width - padLeft - padRight;
  const innerH = height - padTop - padBottom;

  const maxVal = Math.max(4, ...data.map((d) => Math.max(d.events, d.threats)));
  const stepX = data.length > 1 ? innerW / (data.length - 1) : innerW / 2;

  const toX = (i: number) => (data.length === 1 ? padLeft + innerW / 2 : padLeft + i * stepX);
  const toY = (v: number) => padTop + innerH - (v / maxVal) * innerH;

  const eventsPoints = data.map((d, i) => `${toX(i)},${toY(d.events)}`).join(' ');
  const threatsPoints = data.map((d, i) => `${toX(i)},${toY(d.threats)}`).join(' ');
  const eventsArea = `${padLeft},${padTop + innerH} ${eventsPoints} ${toX(data.length - 1)},${padTop + innerH}`;

  const gridTicks = [0, 0.5, 1].map((ratio) => ({
    val: Math.round(maxVal * ratio),
    y: padTop + innerH - ratio * innerH,
  }));

  return (
    <div className="relative w-full">
      <svg viewBox={`0 0 ${width} ${height}`} className="w-full overflow-visible" role="img" aria-label="Security events and threat detections over time">
        <defs>
          <linearGradient id="eventsFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#3B82F6" stopOpacity="0.28" />
            <stop offset="100%" stopColor="#3B82F6" stopOpacity="0.02" />
          </linearGradient>
        </defs>

        {gridTicks.map((t, idx) => (
          <g key={idx}>
            <line x1={padLeft} y1={t.y} x2={width - padRight} y2={t.y} stroke="#1E293B" strokeDasharray="3 3" />
            <text x={padLeft - 8} y={t.y + 4} textAnchor="end" className="fill-slate-500 font-mono text-[10px]">
              {t.val}
            </text>
          </g>
        ))}

        <polygon points={eventsArea} fill="url(#eventsFill)" />
        <polyline fill="none" stroke="#3B82F6" strokeWidth="2" points={eventsPoints} />
        <polyline fill="none" stroke="#8B5CF6" strokeWidth="2.2" points={threatsPoints} />

        {data.map((d, i) => {
          const cx = toX(i);
          const showLabel = data.length <= 8 || i % Math.ceil(data.length / 6) === 0 || i === data.length - 1;
          return (
            <g
              key={d.bucket}
              onMouseEnter={() => setHoveredIdx(i)}
              onMouseLeave={() => setHoveredIdx(null)}
              className="cursor-pointer"
            >
              <rect x={cx - 14} y={padTop} width={28} height={innerH + 10} fill="transparent" />
              <circle cx={cx} cy={toY(d.events)} r={hoveredIdx === i ? 4.5 : 3} fill="#3B82F6" />
              <circle cx={cx} cy={toY(d.threats)} r={hoveredIdx === i ? 4.5 : 3} fill="#A78BFA" />
              {showLabel && (
                <text x={cx} y={height - 10} textAnchor="middle" className="fill-slate-500 font-mono text-[10px]">
                  {d.bucket.slice(6)}
                </text>
              )}
            </g>
          );
        })}
      </svg>

      <div className="mt-2 flex flex-wrap items-center justify-between gap-4 text-xs text-slate-400">
        <div className="flex items-center gap-5">
          <span className="inline-flex items-center gap-2">
            <span className="inline-block h-2 w-4 bg-blue-500" />
            <span>Log Events</span>
          </span>
          <span className="inline-flex items-center gap-2">
            <span className="inline-block h-2 w-4 bg-violet-400" />
            <span>Threat Detections</span>
          </span>
        </div>
        {hoveredIdx !== null && data[hoveredIdx] && (
          <div className="font-mono text-slate-200 tabular-nums">
            {data[hoveredIdx].bucket} · {data[hoveredIdx].events} events · {data[hoveredIdx].threats} threats
          </div>
        )}
      </div>
    </div>
  );
};

export const HorizontalBarChart: React.FC<{
  items: Array<{ label: string; value: number; accent?: 'blue' | 'violet' | 'red' | 'amber' }>;
  emptyLabel?: string;
}> = ({ items, emptyLabel = 'No distribution data available.' }) => {
  if (items.length === 0) {
    return <p className="py-6 text-sm text-slate-500">{emptyLabel}</p>;
  }
  const max = Math.max(1, ...items.map((i) => i.value));
  const colorMap = {
    blue: 'bg-blue-500',
    violet: 'bg-violet-500',
    red: 'bg-red-500',
    amber: 'bg-amber-500',
  };

  return (
    <div className="space-y-3">
      {items.map((item) => {
        const pct = Math.max(3, Math.round((item.value / max) * 100));
        return (
          <div key={item.label} className="space-y-1">
            <div className="flex items-center justify-between text-xs">
              <span className="truncate text-slate-300 pr-3">{item.label}</span>
              <span className="font-mono text-slate-200 tabular-nums">{item.value}</span>
            </div>
            <div className="h-2 w-full overflow-hidden rounded-sm bg-slate-800/80">
              <div
                className={`h-full transition-all duration-200 ${colorMap[item.accent ?? 'blue']}`}
                style={{ width: `${pct}%` }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
};

export const ConfusionMatrixGrid: React.FC<{ matrix: ConfusionMatrix; title: string }> = ({ matrix, title }) => {
  return (
    <div className="space-y-2">
      <div className="text-xs font-medium text-slate-300">{title}</div>
      <div className="grid grid-cols-2 gap-1.5 text-center font-mono text-xs">
        <div className="border border-emerald-500/30 bg-emerald-500/10 p-2.5">
          <div className="text-[11px] text-emerald-300">True Positive</div>
          <div className="mt-1 text-lg font-semibold text-slate-100 tabular-nums">{matrix.tp}</div>
        </div>
        <div className="border border-amber-500/30 bg-amber-500/10 p-2.5">
          <div className="text-[11px] text-amber-300">False Positive</div>
          <div className="mt-1 text-lg font-semibold text-slate-100 tabular-nums">{matrix.fp}</div>
        </div>
        <div className="border border-red-500/30 bg-red-500/10 p-2.5">
          <div className="text-[11px] text-red-300">False Negative</div>
          <div className="mt-1 text-lg font-semibold text-slate-100 tabular-nums">{matrix.fn}</div>
        </div>
        <div className="border border-blue-500/30 bg-blue-500/10 p-2.5">
          <div className="text-[11px] text-blue-300">True Negative</div>
          <div className="mt-1 text-lg font-semibold text-slate-100 tabular-nums">{matrix.tn}</div>
        </div>
      </div>
    </div>
  );
};
