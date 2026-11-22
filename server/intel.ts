import type { ThreatIntelRecord } from '../src/shared/types.ts';
import { isPrivateOrReservedIp } from './features.ts';
import { isValidIp } from './parsers.ts';

const DEMO_THREAT_INTEL: Record<string, Omit<ThreatIntelRecord, 'ip' | 'ipVersion' | 'scope' | 'cidrClass' | 'checkedAt'>> = {
  '185.220.101.45': {
    provenance: 'Demo Intelligence',
    reputation: 'Malicious',
    riskScore: 94,
    asnOrOwner: 'AS205100 (Demo Tor Exit / Proxy Node)',
    country: 'DE',
    tags: ['ssh-bruteforce', 'credential-stuffing', 'anonymizer'],
    summary: 'Synthetic demo intelligence record: high-volume SSH credential guessing source observed in lab dataset.',
  },
  '198.51.100.77': {
    provenance: 'Demo Intelligence',
    reputation: 'Suspicious',
    riskScore: 78,
    asnOrOwner: 'AS64512 (TEST-NET-2 Documentation Block)',
    country: 'US',
    tags: ['port-scanner', 'syn-recon', 'rfc5737-doc'],
    summary: 'Synthetic demo intelligence record: multi-port TCP SYN reconnaissance host in RFC 5737 documentation space.',
  },
  '45.133.1.88': {
    provenance: 'Demo Intelligence',
    reputation: 'Malicious',
    riskScore: 96,
    asnOrOwner: 'AS49877 (Demo Unverified Hosting)',
    country: 'NL',
    tags: ['c2-beacon', 'malware-payload', 'port-4444'],
    summary: 'Synthetic demo intelligence record: simulated command-and-control endpoint associated with encoded PowerShell payloads.',
  },
  '91.240.118.14': {
    provenance: 'Demo Intelligence',
    reputation: 'Malicious',
    riskScore: 88,
    asnOrOwner: 'AS209588 (Demo Scanner Cluster)',
    country: 'RU',
    tags: ['ssh-spray', 'off-hours-auth'],
    summary: 'Synthetic demo intelligence record: automated password spray source targeting root/admin accounts.',
  },
  '203.0.113.54': {
    provenance: 'Demo Intelligence',
    reputation: 'Suspicious',
    riskScore: 71,
    asnOrOwner: 'AS64513 (TEST-NET-3 Documentation Block)',
    country: 'AU',
    tags: ['reconnaissance', 'rfc5737-doc'],
    summary: 'Synthetic demo intelligence record: automated service discovery scanner.',
  },
  '10.0.2.15': {
    provenance: 'Demo Intelligence',
    reputation: 'Benign',
    riskScore: 4,
    asnOrOwner: 'Corporate Workstation Subnet (RFC 1918)',
    country: 'INTERNAL',
    tags: ['internal-host', 'trusted-vpn'],
    summary: 'Internal corporate endpoint address used by authenticated engineering staff.',
  },
  '172.16.4.19': {
    provenance: 'Demo Intelligence',
    reputation: 'Benign',
    riskScore: 3,
    asnOrOwner: 'Internal Backup Services VLAN (RFC 1918)',
    country: 'INTERNAL',
    tags: ['internal-service', 'backup-node'],
    summary: 'Internal scheduled backup runner on private RFC 1918 segment.',
  },
};

export function classifyIpScope(ip: string): {
  ipVersion: 'IPv4' | 'IPv6' | 'Invalid';
  scope: 'Private / Reserved' | 'Public Routable' | 'Invalid';
  cidrClass: string;
} {
  if (!isValidIp(ip)) {
    return { ipVersion: 'Invalid', scope: 'Invalid', cidrClass: 'Invalid IP syntax' };
  }
  const trimmed = ip.trim();
  if (trimmed.includes(':')) {
    const priv = isPrivateOrReservedIp(trimmed);
    return {
      ipVersion: 'IPv6',
      scope: priv ? 'Private / Reserved' : 'Public Routable',
      cidrClass: priv ? 'IPv6 Loopback / ULA / Link-Local' : 'IPv6 Global Unicast',
    };
  }
  const [a, b, c] = trimmed.split('.').map(Number);
  if (a === 10) return { ipVersion: 'IPv4', scope: 'Private / Reserved', cidrClass: 'RFC 1918 Private (10.0.0.0/8)' };
  if (a === 172 && b >= 16 && b <= 31) {
    return { ipVersion: 'IPv4', scope: 'Private / Reserved', cidrClass: 'RFC 1918 Private (172.16.0.0/12)' };
  }
  if (a === 192 && b === 168) {
    return { ipVersion: 'IPv4', scope: 'Private / Reserved', cidrClass: 'RFC 1918 Private (192.168.0.0/16)' };
  }
  if (a === 127) return { ipVersion: 'IPv4', scope: 'Private / Reserved', cidrClass: 'Loopback (127.0.0.0/8)' };
  if (a === 169 && b === 254) {
    return { ipVersion: 'IPv4', scope: 'Private / Reserved', cidrClass: 'Link-Local / Cloud Metadata (169.254.0.0/16)' };
  }
  if (a === 100 && b >= 64 && b <= 127) {
    return { ipVersion: 'IPv4', scope: 'Private / Reserved', cidrClass: 'CGNAT Shared Space (100.64.0.0/10)' };
  }
  if ((a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113)) {
    return { ipVersion: 'IPv4', scope: 'Private / Reserved', cidrClass: 'RFC 5737 Documentation / Test Net' };
  }
  return { ipVersion: 'IPv4', scope: 'Public Routable', cidrClass: 'Public Internet Routable IPv4' };
}

export function analyzeLocalIpIntel(ip: string): ThreatIntelRecord {
  const trimmed = ip.trim();
  const classification = classifyIpScope(trimmed);
  const now = new Date().toISOString();

  if (classification.ipVersion === 'Invalid') {
    return {
      ip: trimmed,
      ...classification,
      provenance: 'Local Classifier Only',
      reputation: 'Unknown',
      riskScore: 0,
      asnOrOwner: 'N/A',
      country: 'N/A',
      tags: ['invalid-format'],
      summary: 'Input is not a valid IPv4 or IPv6 address.',
      checkedAt: now,
    };
  }

  const demoHit = DEMO_THREAT_INTEL[trimmed];
  if (demoHit) {
    return {
      ip: trimmed,
      ...classification,
      ...demoHit,
      checkedAt: now,
    };
  }

  if (classification.scope === 'Private / Reserved') {
    return {
      ip: trimmed,
      ...classification,
      provenance: 'Local Classifier Only',
      reputation: 'Benign',
      riskScore: 10,
      asnOrOwner: 'Private / Non-Routable Address Space',
      country: 'INTERNAL',
      tags: ['private-network', 'non-routable'],
      summary: `Address belongs to ${classification.cidrClass}. Not routable on the public internet.`,
      checkedAt: now,
    };
  }

  return {
    ip: trimmed,
    ...classification,
    provenance: 'Local Classifier Only',
    reputation: 'Unknown',
    riskScore: 35,
    asnOrOwner: 'Public IP (Not in local demo feed)',
    country: 'UNKNOWN',
    tags: ['public-ip', 'unverified-locally'],
    summary: 'Valid public routable IP with no local demo threat match. Use explicit opt-in public RDAP lookup to inspect live registration metadata.',
    checkedAt: now,
  };
}

/**
 * Explicit user-triggered lookup against a fixed allowlisted public RDAP registry endpoint.
 * Strictly blocks private, loopback, link-local, and RFC 5737 addresses to prevent SSRF.
 */
export async function lookupOptInPublicFeed(ip: string): Promise<{
  record: ThreatIntelRecord;
  lookupStatus: 'verified_live' | 'blocked_private' | 'invalid_ip' | 'offline_fallback';
  statusDetail: string;
}> {
  const trimmed = ip.trim();
  const base = analyzeLocalIpIntel(trimmed);

  if (base.ipVersion === 'Invalid') {
    return {
      record: base,
      lookupStatus: 'invalid_ip',
      statusDetail: 'Rejected lookup: invalid IPv4/IPv6 syntax.',
    };
  }

  if (base.scope === 'Private / Reserved') {
    return {
      record: base,
      lookupStatus: 'blocked_private',
      statusDetail: `External lookup blocked for ${base.cidrClass} (private/reserved addresses are never queried externally).`,
    };
  }

  // Fixed allowlisted RDAP endpoint; constructed strictly from validated IP literal
  const encodedIp = encodeURIComponent(trimmed);
  const url = `https://rdap.db.ripe.net/ip/${encodedIp}`;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 3500);

  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: { Accept: 'application/rdap+json, application/json' },
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!response.ok) {
      return {
        record: base,
        lookupStatus: 'offline_fallback',
        statusDetail: `Public RDAP registry returned HTTP ${response.status}; showing local analysis.`,
      };
    }

    const data = (await response.json()) as Record<string, unknown>;
    const name = typeof data.name === 'string' ? data.name : 'Public Registry Allocation';
    const country = typeof data.country === 'string' ? data.country : 'PUBLIC';
    const handle = typeof data.handle === 'string' ? data.handle : trimmed;
    const typeStr = typeof data.type === 'string' ? data.type : 'ALLOCATED';

    const enriched: ThreatIntelRecord = {
      ...base,
      provenance: 'Verified Public Feed',
      asnOrOwner: `${name} (${handle})`,
      country,
      tags: Array.from(new Set([...base.tags, 'rdap-verified', typeStr.toLowerCase()])),
      summary: `Verified via public RIPE RDAP registry: ${name}, network block ${handle} (${country}).`,
      checkedAt: new Date().toISOString(),
    };

    return {
      record: enriched,
      lookupStatus: 'verified_live',
      statusDetail: 'Successfully enriched from public RIPE RDAP registration feed.',
    };
  } catch {
    clearTimeout(timeout);
    return {
      record: base,
      lookupStatus: 'offline_fallback',
      statusDetail: 'Public RDAP feed unreachable or timed out in current network environment; retaining local analysis.',
    };
  }
}
