import React, { useEffect, useState } from 'react';
import { Lock, Play } from 'lucide-react';
import { ConfusionMatrixGrid, HorizontalBarChart } from '../components/Charts';
import { formatUtcTime } from '../components/SeverityText';
import { api } from '../lib/api';
import type { MLEvaluationReport, ModelMetrics, PublicUser } from '../shared/types';

interface MLEvaluationViewProps {
  currentUser: PublicUser | null;
  onRequireAuth: () => void;
}

const MetricRow: React.FC<{ m: ModelMetrics }> = ({ m }) => {
  const pct = (v: number) => `${(v * 100).toFixed(1)}%`;
  return (
    <tr className="hover:bg-slate-800/30">
      <td className="py-2.5 pr-4 font-medium text-slate-100">{m.modelName}</td>
      <td className="py-2.5 pr-4 text-right font-mono text-slate-200 tabular-nums">{pct(m.accuracy)}</td>
      <td className="py-2.5 pr-4 text-right font-mono text-blue-300 tabular-nums">{pct(m.precision)}</td>
      <td className="py-2.5 pr-4 text-right font-mono text-violet-300 tabular-nums">{pct(m.recall)}</td>
      <td className="py-2.5 pr-4 text-right font-mono text-emerald-400 tabular-nums">{pct(m.f1Score)}</td>
      <td className="py-2.5 text-right font-mono text-amber-300 tabular-nums">{pct(m.falsePositiveRate)}</td>
    </tr>
  );
};

export const MLEvaluationView: React.FC<MLEvaluationViewProps> = ({ currentUser, onRequireAuth }) => {
  const [report, setReport] = useState<MLEvaluationReport | null>(null);
  const [preview, setPreview] = useState<
    Array<{ id: string; timestamp: string; sourceIp: string; port: number; category: string; label: 0 | 1 }>
  >([]);
  const [splitRatio, setSplitRatio] = useState(0.75);
  const [seed, setSeed] = useState(2026);
  const [includeFeedback, setIncludeFeedback] = useState(true);
  const [loading, setLoading] = useState(true);
  const [retraining, setRetraining] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        const res = await api.getMlEvaluation();
        setReport(res.evaluation);
        setSplitRatio(res.evaluation.splitRatio);
        setSeed(res.evaluation.seed);
        setPreview(res.datasetPreview);
      } finally {
        setLoading(false);
      }
    };
    void load();
  }, []);

  const handleRetrain = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setStatusMsg(null);
    if (!currentUser || currentUser.role !== 'administrator') {
      onRequireAuth();
      return;
    }
    setRetraining(true);
    try {
      const res = await api.retrainModels({ splitRatio, seed, includeFeedback });
      setReport(res.evaluation);
      setStatusMsg(
        `Retrained Isolation Forest + Logistic Regression on ${res.evaluation.trainCount} training samples and evaluated on ${res.evaluation.testCount} held-out test samples.`
      );
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Retraining failed');
    } finally {
      setRetraining(false);
    }
  };

  if (loading || !report) {
    return <div className="h-72 animate-pulse border border-slate-800 bg-[#111827]" />;
  }

  const isAdmin = currentUser?.role === 'administrator';

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-slate-100">
            Machine Learning Evaluation &amp; Dataset Split Lab
          </h1>
          <p className="mt-1 text-xs text-slate-400">
            Genuine out-of-sample evaluation of Isolation Forest (unsupervised) and Logistic Regression (supervised) on a reproducible labeled dataset.
          </p>
        </div>
        <div className="font-mono text-xs text-slate-400 tabular-nums">
          Evaluated: {formatUtcTime(report.evaluatedAt)}
        </div>
      </div>

      {statusMsg && (
        <div className="border border-emerald-500/40 bg-emerald-500/10 px-4 py-2.5 text-xs text-emerald-200">
          {statusMsg}
        </div>
      )}
      {errorMsg && (
        <div className="border border-red-500/40 bg-red-500/10 px-4 py-2.5 text-xs text-red-200">{errorMsg}</div>
      )}

      {/* Dataset Split & Leakage Prevention Summary */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="border border-slate-800 bg-[#111827] p-4">
          <div className="text-xs text-slate-400">Reproducible Dataset Size</div>
          <div className="mt-1.5 font-mono text-2xl font-semibold text-slate-100 tabular-nums">
            {report.totalDatasetRecords}
          </div>
          <div className="mt-1 text-xs text-slate-400 tabular-nums">
            Seed {report.seed} · {report.feedbackSamplesIncluded} feedback rows
          </div>
        </div>
        <div className="border border-slate-800 bg-[#111827] p-4">
          <div className="text-xs text-slate-400">Stratified Training Split</div>
          <div className="mt-1.5 font-mono text-2xl font-semibold text-blue-300 tabular-nums">{report.trainCount}</div>
          <div className="mt-1 text-xs text-slate-400 tabular-nums">
            {Math.round(report.splitRatio * 100)}% split · {report.trainThreatCount} threats
          </div>
        </div>
        <div className="border border-slate-800 bg-[#111827] p-4">
          <div className="text-xs text-slate-400">Held-Out Test Split</div>
          <div className="mt-1.5 font-mono text-2xl font-semibold text-violet-300 tabular-nums">{report.testCount}</div>
          <div className="mt-1 text-xs text-slate-400 tabular-nums">
            {Math.round((1 - report.splitRatio) * 100)}% split · {report.testThreatCount} threats
          </div>
        </div>
        <div className="border border-slate-800 bg-[#111827] p-4">
          <div className="text-xs text-slate-400">Hybrid Test F1-Score</div>
          <div className="mt-1.5 font-mono text-2xl font-semibold text-emerald-400 tabular-nums">
            {(report.hybridEnsemble.f1Score * 100).toFixed(1)}%
          </div>
          <div className="mt-1 text-xs text-slate-400 tabular-nums">
            FPR: {(report.hybridEnsemble.falsePositiveRate * 100).toFixed(1)}%
          </div>
        </div>
      </div>

      {/* Model Comparison Table */}
      <div className="border border-slate-800 bg-[#111827] p-5">
        <div className="mb-3">
          <h2 className="text-sm font-semibold text-slate-100">Held-Out Test Set Benchmark Comparison</h2>
          <p className="text-xs text-slate-400">
            {report.preprocessingSummary.scalerMethod} · {report.preprocessingSummary.leakagePrevention}
          </p>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 text-slate-400">
              <tr>
                <th className="py-2 pr-4 font-medium">Model</th>
                <th className="py-2 pr-4 font-medium text-right">Accuracy</th>
                <th className="py-2 pr-4 font-medium text-right">Precision</th>
                <th className="py-2 pr-4 font-medium text-right">Recall</th>
                <th className="py-2 pr-4 font-medium text-right">F1-Score</th>
                <th className="py-2 font-medium text-right">False Positive Rate</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              <MetricRow m={report.isolationForest} />
              <MetricRow m={report.logisticRegression} />
              <MetricRow m={report.hybridEnsemble} />
            </tbody>
          </table>
        </div>
      </div>

      {/* Confusion Matrices */}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
        <div className="border border-slate-800 bg-[#111827] p-5">
          <ConfusionMatrixGrid matrix={report.isolationForest.confusionMatrix} title="Isolation Forest Confusion Matrix" />
        </div>
        <div className="border border-slate-800 bg-[#111827] p-5">
          <ConfusionMatrixGrid
            matrix={report.logisticRegression.confusionMatrix}
            title="Logistic Regression Confusion Matrix"
          />
        </div>
        <div className="border border-slate-800 bg-[#111827] p-5">
          <ConfusionMatrixGrid matrix={report.hybridEnsemble.confusionMatrix} title="Hybrid Ensemble Confusion Matrix" />
        </div>
      </div>

      {/* Feature Weights + Retrain Controls */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        <div className="border border-slate-800 bg-[#111827] p-5 lg:col-span-7">
          <h2 className="text-sm font-semibold text-slate-100">Learned Logistic Regression Feature Magnitudes</h2>
          <p className="mb-4 text-xs text-slate-400">Absolute standardized coefficients learned from training partition</p>
          <HorizontalBarChart
            items={report.learnedWeights.map((w) => ({
              label: `${w.label} (${w.weight >= 0 ? '+' : ''}${w.weight.toFixed(2)})`,
              value: Number(w.absWeight.toFixed(2)),
              accent: w.weight >= 0 ? 'violet' : 'blue',
            }))}
          />
        </div>

        <form onSubmit={handleRetrain} className="border border-slate-800 bg-[#111827] p-5 lg:col-span-5 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-100">Train / Test Split &amp; Retraining</h2>
            {!isAdmin && (
              <span className="inline-flex items-center gap-1 text-[11px] text-amber-300">
                <Lock className="h-3 w-3" />
                <span>Admin Required</span>
              </span>
            )}
          </div>
          <p className="text-xs text-slate-400">
            Configure stratified split ratio, random seed, and whether to include analyst True/False Positive alert feedback.
          </p>

          <div>
            <label className="flex justify-between text-xs text-slate-300">
              <span>Training Split Ratio</span>
              <span className="font-mono tabular-nums">
                {Math.round(splitRatio * 100)}% Train / {Math.round((1 - splitRatio) * 100)}% Test
              </span>
            </label>
            <input
              type="range"
              min={0.55}
              max={0.85}
              step={0.05}
              value={splitRatio}
              onChange={(e) => setSplitRatio(Number(e.target.value))}
              className="mt-2 w-full accent-blue-500"
            />
          </div>

          <div>
            <label className="block text-xs text-slate-300">Deterministic PRNG Seed</label>
            <input
              type="number"
              value={seed}
              onChange={(e) => setSeed(Number(e.target.value) || 2026)}
              className="mt-1 w-full border border-slate-700 bg-[#060913] px-3 py-1.5 font-mono text-xs text-slate-100"
            />
          </div>

          <label className="flex items-center gap-2 text-xs text-slate-300">
            <input
              type="checkbox"
              checked={includeFeedback}
              onChange={(e) => setIncludeFeedback(e.target.checked)}
              className="accent-blue-500"
            />
            <span>Include analyst True Positive / False Positive alert feedback</span>
          </label>

          <button
            type="submit"
            disabled={retraining}
            className="inline-flex w-full items-center justify-center gap-2 bg-blue-600 px-4 py-2 text-xs font-medium text-white hover:bg-blue-500 disabled:opacity-50"
          >
            <Play className="h-3.5 w-3.5" />
            <span>
              {retraining
                ? 'Training & Evaluating...'
                : isAdmin
                  ? 'Retrain Models & Evaluate Test Split'
                  : 'Sign In as Admin to Retrain'}
            </span>
          </button>
        </form>
      </div>

      {/* Sample Labeled Benchmark Preview */}
      <div className="border border-slate-800 bg-[#111827] p-5">
        <h2 className="mb-3 text-sm font-semibold text-slate-100">Reproducible Labeled Benchmark Dataset Sample</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 text-slate-400">
              <tr>
                <th className="py-2 pr-3 font-medium">ID</th>
                <th className="py-2 pr-3 font-medium">Timestamp</th>
                <th className="py-2 pr-3 font-medium">Source IP</th>
                <th className="py-2 pr-3 font-medium">Port</th>
                <th className="py-2 pr-3 font-medium">Category</th>
                <th className="py-2 font-medium text-right">Ground Truth Label</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {preview.map((row) => (
                <tr key={row.id}>
                  <td className="py-2 pr-3 font-mono text-slate-400">{row.id}</td>
                  <td className="py-2 pr-3 font-mono text-slate-300 tabular-nums">{formatUtcTime(row.timestamp)}</td>
                  <td className="py-2 pr-3 font-mono text-slate-200 tabular-nums">{row.sourceIp}</td>
                  <td className="py-2 pr-3 font-mono text-slate-300 tabular-nums">{row.port}</td>
                  <td className="py-2 pr-3 text-slate-200">{row.category}</td>
                  <td className="py-2 text-right font-mono">
                    <span className={row.label === 1 ? 'text-red-400' : 'text-emerald-400'}>
                      {row.label === 1 ? '1 (Threat)' : '0 (Benign)'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
