import React, { useEffect, useState } from 'react';
import { Lock, RotateCcw, Shield } from 'lucide-react';
import { api } from '../lib/api';
import type { PublicUser, SensitivityConfig, SensitivityLevel } from '../shared/types';

interface SettingsViewProps {
  currentUser: PublicUser | null;
  compactDensity: boolean;
  onToggleCompact: (val: boolean) => void;
  onRequireAuth: () => void;
  onDataReset: () => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({
  currentUser,
  compactDensity,
  onToggleCompact,
  onRequireAuth,
  onDataReset,
}) => {
  const [sensitivity, setSensitivity] = useState<SensitivityConfig | null>(null);
  const [counts, setCounts] = useState({ eventsCount: 0, alertsCount: 0 });
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  const loadSettings = async () => {
    setLoading(true);
    try {
      const res = await api.getSettings();
      setSensitivity(res.sensitivity);
      setCounts({ eventsCount: res.eventsCount, alertsCount: res.alertsCount });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadSettings();
  }, []);

  const isAdmin = currentUser?.role === 'administrator';

  const handleSensitivityChange = async (level: SensitivityLevel) => {
    if (!isAdmin) {
      onRequireAuth();
      return;
    }
    setBusy(true);
    setMessage(null);
    try {
      const res = await api.updateSensitivity(level);
      setSensitivity(res.sensitivity);
      setMessage({ type: 'ok', text: `Detection sensitivity updated to "${level}".` });
    } catch (err) {
      setMessage({ type: 'err', text: err instanceof Error ? err.message : 'Update failed' });
    } finally {
      setBusy(false);
    }
  };

  const handleReset = async () => {
    if (!isAdmin) {
      onRequireAuth();
      return;
    }
    setBusy(true);
    setMessage(null);
    try {
      const res = await api.resetDemoData();
      setCounts({ eventsCount: res.eventsCount, alertsCount: res.alertsCount });
      setMessage({ type: 'ok', text: res.message });
      onDataReset();
    } catch (err) {
      setMessage({ type: 'err', text: err instanceof Error ? err.message : 'Reset failed' });
    } finally {
      setBusy(false);
    }
  };

  if (loading || !sensitivity) {
    return <div className="h-64 animate-pulse border border-slate-800 bg-[#111827]" />;
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-slate-100">Settings &amp; Platform Governance</h1>
          <p className="mt-1 text-xs text-slate-400">
            Configure detection sensitivity thresholds, reset demonstration storage, and inspect SentinelForge architecture details.
          </p>
        </div>
        {!isAdmin && (
          <button
            type="button"
            onClick={onRequireAuth}
            className="inline-flex items-center gap-1.5 border border-violet-500/50 bg-violet-500/10 px-3.5 py-2 text-xs font-medium text-violet-200 hover:bg-violet-500/20"
          >
            <Lock className="h-3.5 w-3.5" />
            <span>Sign In as Demo Administrator</span>
          </button>
        )}
      </div>

      {message && (
        <div
          className={`border px-4 py-2.5 text-xs ${
            message.type === 'ok'
              ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200'
              : 'border-red-500/40 bg-red-500/10 text-red-200'
          }`}
        >
          {message.text}
        </div>
      )}

      {/* Detection Sensitivity */}
      <div className="border border-slate-800 bg-[#111827] p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">Hybrid Detection Sensitivity</h2>
            <p className="text-xs text-slate-400">
              Adjusts rule thresholds, Isolation Forest anomaly cutoff, and Logistic Regression probability threshold (Administrator role required).
            </p>
          </div>
          <span className="font-mono text-xs text-violet-300 uppercase">{sensitivity.level}</span>
        </div>

        <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
          {(['low', 'balanced', 'high'] as const).map((lvl) => {
            const active = sensitivity.level === lvl;
            return (
              <button
                key={lvl}
                type="button"
                disabled={busy}
                onClick={() => void handleSensitivityChange(lvl)}
                className={`border p-4 text-left transition-colors ${
                  active
                    ? 'border-blue-500 bg-blue-600/15'
                    : 'border-slate-800 bg-[#060913] hover:border-slate-700'
                }`}
              >
                <div className="text-xs font-semibold capitalize text-slate-100">{lvl} Sensitivity</div>
                <div className="mt-1 text-[11px] text-slate-400">
                  {lvl === 'low'
                    ? 'Minimizes false positives; triggers only on strong multi-signal bursts.'
                    : lvl === 'balanced'
                      ? 'Recommended default balancing precision and recall.'
                      : 'Aggressive anomaly & early brute-force sensitivity.'}
                </div>
              </button>
            );
          })}
        </div>

        <div className="grid grid-cols-2 gap-4 border-t border-slate-800 pt-4 font-mono text-xs text-slate-300 sm:grid-cols-5">
          <div>
            <div className="text-[11px] text-slate-500">IForest Cutoff</div>
            <div>{sensitivity.anomalyThreshold}</div>
          </div>
          <div>
            <div className="text-[11px] text-slate-500">LR Prob Cutoff</div>
            <div>{sensitivity.mlProbabilityThreshold}</div>
          </div>
          <div>
            <div className="text-[11px] text-slate-500">Rule Cutoff</div>
            <div>{sensitivity.ruleAlertThreshold}</div>
          </div>
          <div>
            <div className="text-[11px] text-slate-500">Brute-Force Burst</div>
            <div>{sensitivity.bruteForceThreshold} fails</div>
          </div>
          <div>
            <div className="text-[11px] text-slate-500">Port Scan Threshold</div>
            <div>{sensitivity.portScanThreshold} ports</div>
          </div>
        </div>
      </div>

      {/* UI Preferences & Demo Reset */}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        <div className="border border-slate-800 bg-[#111827] p-6 space-y-4">
          <h2 className="text-sm font-semibold text-slate-100">Interface &amp; Storage</h2>
          <label className="flex items-center justify-between border border-slate-800 bg-[#060913] p-3 text-xs">
            <span className="text-slate-300">Compact workspace spacing</span>
            <input
              type="checkbox"
              checked={compactDensity}
              onChange={(e) => onToggleCompact(e.target.checked)}
              className="accent-blue-500"
            />
          </label>
          <div className="text-xs text-slate-400 tabular-nums">
            Active local JSON persistence contains <span className="font-mono text-slate-200">{counts.eventsCount}</span> events and{' '}
            <span className="font-mono text-slate-200">{counts.alertsCount}</span> alerts.
          </div>
          <button
            type="button"
            disabled={busy}
            onClick={() => void handleReset()}
            className="inline-flex items-center gap-2 border border-red-500/50 bg-red-500/10 px-4 py-2 text-xs font-medium text-red-200 hover:bg-red-500/20"
          >
            <RotateCcw className="h-3.5 w-3.5" />
            <span>{isAdmin ? 'Reset Sample Demonstration Data' : 'Sign In as Admin to Reset Data'}</span>
          </button>
        </div>

        <div className="border border-slate-800 bg-[#111827] p-6 space-y-3">
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-blue-400" />
            <h2 className="text-sm font-semibold text-slate-100">About SENTINELFORGE</h2>
          </div>
          <p className="text-xs leading-relaxed text-slate-300">
            SENTINELFORGE is an academic fourth-year cybersecurity engineering prototype built for defensive log analysis, explainable machine learning research, MITRE ATT&amp;CK mapping, and digital forensics workflow training.
          </p>
          <div className="space-y-1 border-t border-slate-800 pt-3 text-xs text-slate-400">
            <div>Architecture: React 19 + TypeScript + Express + Local JSON Store</div>
            <div>ML Models: Seeded Isolation Forest + L2 Logistic Regression (Train/Test Split)</div>
            <div>External Billing / Cloud Dependencies: None (100% Local-First)</div>
          </div>
        </div>
      </div>
    </div>
  );
};
