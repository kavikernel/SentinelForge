import React, { useEffect, useState } from 'react';
import { Globe, Search } from 'lucide-react';
import { formatUtcTime } from '../components/SeverityText';
import { api } from '../lib/api';
import type { ThreatIntelRecord } from '../shared/types';

export const ThreatIntelView: React.FC = () => {
  const [records, setRecords] = useState<ThreatIntelRecord[]>([]);
  const [ipInput, setIpInput] = useState('');
  const [includePublicFeed, setIncludePublicFeed] = useState(false);
  const [lookupResult, setLookupResult] = useState<{
    record: ThreatIntelRecord;
    lookupStatus: string;
    statusDetail: string;
  } | null>(null);
  const [loading, setLoading] = useState(true);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadIntel = async () => {
    setLoading(true);
    try {
      const res = await api.getIntel();
      setRecords(res.records);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadIntel();
  }, []);

  const handleLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    setChecking(true);
    setError(null);
    try {
      const res = await api.lookupIntel(ipInput, includePublicFeed);
      setLookupResult(res);
      await loadIntel();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'IP lookup failed');
    } finally {
      setChecking(false);
    }
  };

  const repColor = (rep: ThreatIntelRecord['reputation']) => {
    if (rep === 'Malicious') return 'text-red-400';
    if (rep === 'Suspicious') return 'text-amber-400';
    if (rep === 'Benign') return 'text-emerald-400';
    return 'text-slate-400';
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-slate-100">Threat Intelligence &amp; IP Reputation</h1>
        <p className="mt-1 text-xs text-slate-400">
          Analyzes IPs from ingested logs locally. Outbound public RDAP lookups are strictly opt-in and never target private/reserved ranges.
        </p>
      </div>

      {/* Manual IP Lookup Form */}
      <form onSubmit={handleLookup} className="border border-slate-800 bg-[#111827] p-5 space-y-4">
        <div className="flex flex-wrap items-end gap-3">
          <div className="flex-1 min-w-[240px]">
            <label className="block text-xs font-medium text-slate-300">Analyze IPv4 / IPv6 Address</label>
            <div className="relative mt-1">
              <Search className="pointer-events-none absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
              <input
                type="text"
                required
                value={ipInput}
                onChange={(e) => setIpInput(e.target.value)}
                placeholder="e.g. 185.220.101.45, 192.168.1.50, or 8.8.8.8"
                className="w-full border border-slate-700 bg-[#060913] py-2 pl-9 pr-3 font-mono text-xs text-slate-100 focus:border-blue-500 focus:outline-none"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={checking}
            className="bg-blue-600 px-5 py-2 text-xs font-medium text-white hover:bg-blue-500 disabled:opacity-50"
          >
            {checking ? 'Checking...' : 'Analyze IP'}
          </button>
        </div>

        <label className="flex items-center gap-2 text-xs text-slate-300">
          <input
            type="checkbox"
            checked={includePublicFeed}
            onChange={(e) => setIncludePublicFeed(e.target.checked)}
            className="accent-blue-500"
          />
          <Globe className="h-3.5 w-3.5 text-blue-400" />
          <span>
            Opt-in: Query public RIPE RDAP registration feed for public routable IPs (offline/private IPs remain local-only)
          </span>
        </label>

        {error && <p className="text-xs text-red-400">{error}</p>}

        {lookupResult && (
          <div className="border-t border-slate-800 pt-4 text-xs">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="font-mono text-sm font-semibold text-slate-100">{lookupResult.record.ip}</div>
              <div className="font-mono text-slate-400">
                Provenance: <span className="text-violet-300">{lookupResult.record.provenance}</span>
              </div>
            </div>
            <p className="mt-1 text-slate-300">{lookupResult.statusDetail}</p>
            <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-3 text-slate-400">
              <div>Scope: {lookupResult.record.scope}</div>
              <div>CIDR Class: {lookupResult.record.cidrClass}</div>
              <div>
                Reputation: <span className={repColor(lookupResult.record.reputation)}>{lookupResult.record.reputation}</span> ({lookupResult.record.riskScore}/100)
              </div>
            </div>
            <p className="mt-2 text-slate-300">{lookupResult.record.summary}</p>
          </div>
        )}
      </form>

      {/* Observed IP Intel Table */}
      <div className="border border-slate-800 bg-[#111827] p-5">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">Analyzed IP Intelligence Directory</h2>
            <p className="text-xs text-slate-400">Clearly separates synthetic Demo Intelligence from Verified Public Feed records</p>
          </div>
        </div>

        {loading ? (
          <div className="h-40 animate-pulse bg-slate-800/40" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800 text-slate-400">
                <tr>
                  <th className="py-2 pr-3 font-medium">IP Address</th>
                  <th className="py-2 pr-3 font-medium">Scope / Class</th>
                  <th className="py-2 pr-3 font-medium">Provenance</th>
                  <th className="py-2 pr-3 font-medium">Reputation</th>
                  <th className="py-2 pr-3 font-medium text-right">Risk</th>
                  <th className="py-2 pr-3 font-medium">Owner / ASN</th>
                  <th className="py-2 font-medium text-right">Checked</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {records.map((rec) => (
                  <tr key={rec.ip} className="hover:bg-slate-800/30">
                    <td className="py-2.5 pr-3 font-mono text-slate-100 tabular-nums">{rec.ip}</td>
                    <td className="py-2.5 pr-3 text-slate-300">
                      <div>{rec.scope}</div>
                      <div className="text-[11px] text-slate-500">{rec.cidrClass}</div>
                    </td>
                    <td className="py-2.5 pr-3 font-mono text-[11px] text-violet-300">{rec.provenance}</td>
                    <td className={`py-2.5 pr-3 font-medium ${repColor(rec.reputation)}`}>{rec.reputation}</td>
                    <td className="py-2.5 pr-3 text-right font-mono text-slate-200 tabular-nums">{rec.riskScore}</td>
                    <td className="max-w-xs truncate py-2.5 pr-3 text-slate-300" title={rec.asnOrOwner}>
                      {rec.asnOrOwner}
                    </td>
                    <td className="py-2.5 text-right font-mono text-slate-400 tabular-nums">
                      {formatUtcTime(rec.checkedAt)}
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
