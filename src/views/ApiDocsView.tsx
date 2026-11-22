import React, { useEffect, useState } from 'react';
import { Terminal } from 'lucide-react';
import { api } from '../lib/api';

export const ApiDocsView: React.FC = () => {
  const [docs, setDocs] = useState<{
    version: string;
    baseUrl: string;
    authScheme: string;
    endpoints: Array<{ method: string; path: string; role: string; description: string }>;
  } | null>(null);
  const [healthResult, setHealthResult] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        const res = await api.getDocs();
        setDocs(res);
      } finally {
        setLoading(false);
      }
    };
    void load();
  }, []);

  const pingHealth = async () => {
    const res = await fetch('/api/health');
    const json = await res.json();
    setHealthResult(JSON.stringify(json, null, 2));
  };

  if (loading || !docs) {
    return <div className="h-64 animate-pulse border border-slate-800 bg-[#111827]" />;
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-slate-100">REST API Documentation &amp; Test Guide</h1>
          <p className="mt-1 text-xs text-slate-400">
            {docs.authScheme}
          </p>
        </div>

        <button
          type="button"
          onClick={() => void pingHealth()}
          className="inline-flex items-center gap-2 bg-blue-600 px-4 py-2 text-xs font-medium text-white hover:bg-blue-500"
        >
          <Terminal className="h-3.5 w-3.5" />
          <span>Test GET /api/health</span>
        </button>
      </div>

      {healthResult && (
        <pre className="border border-emerald-500/40 bg-[#060913] p-4 font-mono text-xs text-emerald-300 overflow-x-auto">
          {healthResult}
        </pre>
      )}

      <div className="border border-slate-800 bg-[#111827] p-5">
        <h2 className="mb-3 text-sm font-semibold text-slate-100">Express Backend Endpoints ({docs.endpoints.length})</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 text-slate-400">
              <tr>
                <th className="py-2 pr-3 font-medium">Method</th>
                <th className="py-2 pr-3 font-medium">Endpoint</th>
                <th className="py-2 pr-3 font-medium">RBAC Scope</th>
                <th className="py-2 font-medium">Behavior</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {docs.endpoints.map((ep) => (
                <tr key={`${ep.method}-${ep.path}`} className="hover:bg-slate-800/30">
                  <td className="py-2.5 pr-3 font-mono font-semibold text-blue-400">{ep.method}</td>
                  <td className="py-2.5 pr-3 font-mono text-slate-100">{ep.path}</td>
                  <td className="py-2.5 pr-3 font-mono text-violet-300">{ep.role}</td>
                  <td className="py-2.5 text-slate-300">{ep.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="border border-slate-800 bg-[#111827] p-5 space-y-2">
        <h2 className="text-sm font-semibold text-slate-100">Automated Backend Verification Suite</h2>
        <p className="text-xs text-slate-400">
          Run the automated Node test suite covering log parsers, train-only scaler leakage prevention, Isolation Forest, Logistic Regression metrics, RBAC 401/403 checks, audit logging, and SSRF protection:
        </p>
        <pre className="border border-slate-800 bg-[#060913] p-3 font-mono text-xs text-slate-200">
          npm test
        </pre>
      </div>
    </div>
  );
};
