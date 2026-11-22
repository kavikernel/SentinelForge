import type { EventFeatures } from '../src/shared/types.ts';
import type { ParsedRawEvent } from './parsers.ts';

export const FEATURE_METADATA: Array<{ key: keyof EventFeatures; label: string }> = [
  { key: 'failedAuthCountIp', label: 'IP Failed Auth Burst' },
  { key: 'distinctPortsIp', label: 'Distinct Ports Targeted' },
  { key: 'ipEventBurstCount', label: 'Source IP Frequency' },
  { key: 'isOffHours', label: 'Off-Hours Access (00:00–05:59 UTC)' },
  { key: 'privilegeKeywordScore', label: 'Privilege Escalation Signal' },
  { key: 'malwareKeywordScore', label: 'Malware / Payload Signal' },
  { key: 'suspiciousPortScore', label: 'High-Risk Service Port' },
  { key: 'isPublicSourceIp', label: 'External Public Source IP' },
  { key: 'isFailureStatus', label: 'Failure / Denied Outcome' },
  { key: 'interArrivalZScore', label: 'Temporal Burst Z-Score' },
];

export interface FeatureScaler {
  means: number[];
  stds: number[];
}

export function isPrivateOrReservedIp(ip: string): boolean {
  const v = ip.trim();
  if (v === '::1' || v.toLowerCase().startsWith('fe80:') || v.toLowerCase().startsWith('fc') || v.toLowerCase().startsWith('fd')) {
    return true;
  }
  const parts = v.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return false;
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

const PRIVILEGE_TERMS = ['sudo', 'su ', 'root', 'chmod +s', 'setuid', '/etc/shadow', '/etc/sudoers', 'whoami', 'admin_role', 'escalat', 'token_impersonat', 'wheel'];
const MALWARE_TERMS = ['mimikatz', 'powershell -enc', 'wget http', 'curl | sh', 'bash -i', '/dev/tcp', 'ransom', 'trojan', 'c2_beacon', 'beacon', 'reverse_shell', 'payload', 'xmrig', 'cobalt', 'meterpreter'];
const HIGH_RISK_PORTS = new Set([22, 23, 3389, 4444, 445, 135, 139, 1433, 3306, 5900, 6667, 1337, 8443, 9001, 31337]);

function keywordScore(text: string, terms: string[]): number {
  const lower = text.toLowerCase();
  let matches = 0;
  for (const term of terms) {
    if (lower.includes(term)) matches++;
  }
  return Math.min(1, matches / 2);
}

export function extractEventFeatures(events: ParsedRawEvent[]): EventFeatures[] {
  const failedByIp = new Map<string, number>();
  const portsByIp = new Map<string, Set<number>>();
  const countByIp = new Map<string, number>();

  for (const ev of events) {
    countByIp.set(ev.sourceIp, (countByIp.get(ev.sourceIp) ?? 0) + 1);
    if (!portsByIp.has(ev.sourceIp)) portsByIp.set(ev.sourceIp, new Set());
    if (ev.destinationPort > 0) portsByIp.get(ev.sourceIp)!.add(ev.destinationPort);

    const lower = `${ev.eventType} ${ev.action} ${ev.message}`.toLowerCase();
    const isNonAuthCategory =
      ev.eventType.toUpperCase() === 'PORT_PROBE' ||
      ev.eventType.toUpperCase() === 'MALWARE_SIGNAL' ||
      ev.eventType.toUpperCase() === 'PRIVILEGE_ACTION' ||
      lower.includes('syn scan') ||
      lower.includes('c2_beacon');
    const isFailedAuth =
      !isNonAuthCategory &&
      (ev.statusCode === 401 ||
        lower.includes('failed password') ||
        lower.includes('authentication failure') ||
        lower.includes('invalid user') ||
        (lower.includes('auth') && (lower.includes('failed') || lower.includes('denied'))));
    if (isFailedAuth) {
      failedByIp.set(ev.sourceIp, (failedByIp.get(ev.sourceIp) ?? 0) + 1);
    }
  }

  const ipCounts = Array.from(countByIp.values());
  const meanIpCount = ipCounts.length > 0 ? ipCounts.reduce((a, b) => a + b, 0) / ipCounts.length : 1;
  const varianceIpCount =
    ipCounts.length > 1
      ? ipCounts.reduce((acc, c) => acc + (c - meanIpCount) ** 2, 0) / ipCounts.length
      : 1;
  const stdIpCount = Math.max(0.5, Math.sqrt(varianceIpCount));

  return events.map((ev) => {
    const combinedText = `${ev.eventType} ${ev.action} ${ev.message}`;
    const lower = combinedText.toLowerCase();
    const hour = new Date(ev.timestamp).getUTCHours();
    const isOffHours = hour >= 0 && hour <= 5 ? 1 : 0;

    const ipFreq = countByIp.get(ev.sourceIp) ?? 1;
    const zScore = Math.max(0, Math.min(6, (ipFreq - meanIpCount) / stdIpCount));

    const isFailure =
      ev.statusCode >= 400 ||
      ev.action.toUpperCase() === 'DENIED' ||
      ev.action.toUpperCase() === 'BLOCKED' ||
      ev.action.toUpperCase() === 'FAILED' ||
      lower.includes('failed') ||
      lower.includes('denied')
        ? 1
        : 0;

    let portScore = 0;
    if (ev.destinationPort === 4444 || ev.destinationPort === 1337 || ev.destinationPort === 31337) {
      portScore = 1;
    } else if (HIGH_RISK_PORTS.has(ev.destinationPort)) {
      portScore = 0.6;
    }

    return {
      failedAuthCountIp: failedByIp.get(ev.sourceIp) ?? 0,
      distinctPortsIp: portsByIp.get(ev.sourceIp)?.size ?? 1,
      ipEventBurstCount: ipFreq,
      isOffHours,
      privilegeKeywordScore: keywordScore(combinedText, PRIVILEGE_TERMS),
      malwareKeywordScore: keywordScore(combinedText, MALWARE_TERMS),
      suspiciousPortScore: portScore,
      isPublicSourceIp: isPrivateOrReservedIp(ev.sourceIp) ? 0 : 1,
      isFailureStatus: isFailure,
      interArrivalZScore: Number(zScore.toFixed(3)),
    };
  });
}

export function featuresToVector(f: EventFeatures): number[] {
  return FEATURE_METADATA.map((m) => f[m.key]);
}

export function fitScaler(vectors: number[][]): FeatureScaler {
  if (vectors.length === 0) {
    return { means: FEATURE_METADATA.map(() => 0), stds: FEATURE_METADATA.map(() => 1) };
  }
  const dims = vectors[0].length;
  const means = new Array<number>(dims).fill(0);
  const stds = new Array<number>(dims).fill(1);

  for (const row of vectors) {
    for (let j = 0; j < dims; j++) means[j] += row[j];
  }
  for (let j = 0; j < dims; j++) means[j] /= vectors.length;

  for (const row of vectors) {
    for (let j = 0; j < dims; j++) {
      stds[j] += (row[j] - means[j]) ** 2;
    }
  }
  for (let j = 0; j < dims; j++) {
    stds[j] = Math.sqrt(stds[j] / vectors.length);
    if (stds[j] < 1e-6) stds[j] = 1;
  }

  return { means, stds };
}

export function transformWithScaler(vectors: number[][], scaler: FeatureScaler): number[][] {
  return vectors.map((row) =>
    row.map((val, j) => Number(((val - scaler.means[j]) / scaler.stds[j]).toFixed(5)))
  );
}
