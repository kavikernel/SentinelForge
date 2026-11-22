import { extractEventFeatures, featuresToVector } from './features.ts';
import { createSeededRng } from './mlEngine.ts';
import type { ParsedRawEvent } from './parsers.ts';

export interface LabeledDatasetRecord {
  id: string;
  event: ParsedRawEvent;
  vector: number[];
  label: 0 | 1;
  category: string;
}

/**
 * Generates a reproducible 240-record labeled cybersecurity benchmark dataset
 * using a fixed PRNG seed (2026) so train/test splits and ML evaluations are deterministic.
 */
export function buildReproducibleLabeledDataset(seed = 2026): LabeledDatasetRecord[] {
  const rng = createSeededRng(seed);
  const baseTime = Date.UTC(2026, 10, 20, 8, 0, 0);

  const pick = <T,>(arr: T[]): T => arr[Math.floor(rng() * arr.length)];
  const rawEvents: Array<{ event: ParsedRawEvent; label: 0 | 1; category: string }> = [];

  const benignIps = Array.from({ length: 50 }, (_, idx) => {
    const subnet = 2 + Math.floor(idx / 10);
    const host = 10 + (idx % 10) * 3;
    return `10.0.${subnet}.${host}`;
  });
  const benignUsers = ['alice.chen', 'david.kumar', 'sara.miller', 'svc-backup', 'deploy-ci'];
  const benignMsgs = [
    'HTTPS API request completed 200 OK',
    'User session refreshed successfully via SSO',
    'Scheduled health check passed on internal microservice',
    'Authorized SSH key login from corporate VPN subnet',
    'Database read query executed within nominal latency',
  ];

  // 140 Benign events distributed across corporate client IPs (1-4 events per IP)
  for (let i = 0; i < 140; i++) {
    const ts = new Date(baseTime + i * 180_000 + Math.floor(rng() * 30_000)).toISOString();
    const hourOffset = 8 + Math.floor(rng() * 10);
    const adjusted = new Date(ts);
    adjusted.setUTCHours(hourOffset);
    const srcIp = pick(benignIps);
    rawEvents.push({
      label: 0,
      category: 'Benign',
      event: {
        timestamp: adjusted.toISOString(),
        sourceIp: srcIp,
        destinationIp: '10.0.1.10',
        destinationPort: pick([443, 443, 80, 5432, 22]),
        protocol: 'TCP',
        username: pick(benignUsers),
        eventType: 'NORMAL_TRAFFIC',
        action: 'ALLOW',
        statusCode: 200,
        message: pick(benignMsgs),
        rawLine: `${adjusted.toISOString()} ALLOW ${srcIp} -> 10.0.1.10`,
        groundTruthLabel: 0,
      },
    });
  }

  // 28 Brute Force events across 4 attacker IPs
  const bruteIps = ['185.220.101.45', '45.155.205.91', '194.26.135.72', '91.240.118.14'];
  for (let i = 0; i < 28; i++) {
    const ip = bruteIps[i % bruteIps.length];
    const ts = new Date(baseTime + 3_600_000 + i * 4_000).toISOString();
    rawEvents.push({
      label: 1,
      category: 'Brute Force',
      event: {
        timestamp: ts,
        sourceIp: ip,
        destinationIp: '10.0.1.12',
        destinationPort: 22,
        protocol: 'TCP',
        username: pick(['root', 'admin', 'ubuntu', 'postgres']),
        eventType: 'AUTH_FAILURE',
        action: 'FAILED',
        statusCode: 401,
        message: 'Failed password for invalid user root via sshd',
        rawLine: `${ts} sshd Failed password from ${ip} port 22`,
        groundTruthLabel: 1,
      },
    });
  }

  // 24 Port Scanning events across 3 scanner IPs
  const scanIps = ['198.51.100.77', '203.0.113.54', '103.145.22.19'];
  const scanPorts = [21, 22, 23, 25, 80, 139, 443, 445, 1433, 3306, 3389, 8080];
  for (let i = 0; i < 24; i++) {
    const ip = scanIps[i % scanIps.length];
    const port = scanPorts[i % scanPorts.length];
    const ts = new Date(baseTime + 7_200_000 + i * 1_500).toISOString();
    rawEvents.push({
      label: 1,
      category: 'Port Scanning',
      event: {
        timestamp: ts,
        sourceIp: ip,
        destinationIp: '10.0.1.15',
        destinationPort: port,
        protocol: 'TCP',
        username: 'unknown',
        eventType: 'PORT_PROBE',
        action: 'DENIED',
        statusCode: 403,
        message: `SYN probe blocked on destination port ${port}`,
        rawLine: `${ts} firewall DENIED SYN ${ip} -> 10.0.1.15:${port}`,
        groundTruthLabel: 1,
      },
    });
  }

  // 18 Privilege Escalation events
  for (let i = 0; i < 18; i++) {
    const ts = new Date(baseTime + 10_800_000 + i * 25_000).toISOString();
    const d = new Date(ts);
    d.setUTCHours(2);
    rawEvents.push({
      label: 1,
      category: 'Privilege Escalation',
      event: {
        timestamp: d.toISOString(),
        sourceIp: pick(['185.220.101.45', '172.16.8.99']),
        destinationIp: '10.0.1.20',
        destinationPort: 22,
        protocol: 'TCP',
        username: pick(['www-data', 'guest_svc', 'dev_temp']),
        eventType: 'PRIVILEGE_ACTION',
        action: 'DENIED',
        statusCode: 403,
        message: pick([
          'sudo: unauthorized user attempted to read /etc/shadow',
          'Privilege escalation attempt: chmod +s /bin/bash executed',
          'Attempted modification of /etc/sudoers by non-wheel user',
        ]),
        rawLine: `${d.toISOString()} sudo escalation attempt`,
        groundTruthLabel: 1,
      },
    });
  }

  // 18 Malware / C2 indicator events
  for (let i = 0; i < 18; i++) {
    const ts = new Date(baseTime + 14_400_000 + i * 15_000).toISOString();
    const d = new Date(ts);
    d.setUTCHours(3);
    rawEvents.push({
      label: 1,
      category: 'Malware Indicators',
      event: {
        timestamp: d.toISOString(),
        sourceIp: pick(['45.133.1.88', '194.26.135.72']),
        destinationIp: '10.0.1.30',
        destinationPort: pick([4444, 1337, 31337]),
        protocol: 'TCP',
        username: 'svc-web',
        eventType: 'MALWARE_SIGNAL',
        action: 'BLOCKED',
        statusCode: 403,
        message: pick([
          'Outbound c2_beacon detected executing powershell -enc payload',
          'Blocked reverse_shell /dev/tcp connection after curl | sh',
          'Endpoint alert: mimikatz credential dump signature blocked',
        ]),
        rawLine: `${d.toISOString()} EDR blocked C2 payload`,
        groundTruthLabel: 1,
      },
    });
  }

  // 12 Off-hours Suspicious Authentication events
  for (let i = 0; i < 12; i++) {
    const d = new Date(baseTime + 18_000_000 + i * 60_000);
    d.setUTCHours(1 + (i % 4));
    rawEvents.push({
      label: 1,
      category: 'Suspicious Authentication',
      event: {
        timestamp: d.toISOString(),
        sourceIp: pick(['91.240.118.14', '203.0.113.88']),
        destinationIp: '10.0.1.10',
        destinationPort: 3389,
        protocol: 'TCP',
        username: 'admin-finance',
        eventType: 'AUTH_EVENT',
        action: 'FAILED',
        statusCode: 401,
        message: 'Off-hours remote administrative authentication failure from unverified external IP',
        rawLine: `${d.toISOString()} RDP auth anomaly`,
        groundTruthLabel: 1,
      },
    });
  }

  const extracted = extractEventFeatures(rawEvents.map((r) => r.event));
  return rawEvents.map((r, idx) => ({
    id: `ds-${idx + 1}`,
    event: r.event,
    vector: featuresToVector(extracted[idx]),
    label: r.label,
    category: r.category,
  }));
}

export const SAMPLE_DATASETS: Record<
  'bruteforce_lateral_csv' | 'firewall_portscan_json' | 'ssh_privilege_txt',
  { name: string; filename: string; format: 'csv' | 'json' | 'txt'; description: string; content: string }
> = {
  bruteforce_lateral_csv: {
    name: 'Auth Brute-Force & Lateral Escalation (CSV)',
    filename: 'sample_auth_logs.csv',
    format: 'csv',
    description: '22 synthetic security events modeling normal office traffic followed by an external SSH brute-force burst, off-hours admin login, and sudo escalation.',
    content: [
      'timestamp,source_ip,destination_ip,destination_port,protocol,username,event_type,action,status_code,message',
      '2026-11-21T09:10:00Z,10.0.2.15,10.0.1.10,443,TCP,alice.chen,HTTP_ACCESS,ALLOW,200,Authenticated dashboard session started',
      '2026-11-21T09:14:20Z,10.0.2.28,10.0.1.10,443,TCP,david.kumar,HTTP_ACCESS,ALLOW,200,Report export downloaded',
      '2026-11-21T09:22:05Z,192.168.10.22,10.0.1.12,22,TCP,deploy-ci,AUTH_EVENT,ALLOW,200,Authorized CI deployment key accepted',
      '2026-11-21T02:11:02Z,185.220.101.45,10.0.1.12,22,TCP,root,AUTH_FAILURE,FAILED,401,Failed password for invalid user root',
      '2026-11-21T02:11:05Z,185.220.101.45,10.0.1.12,22,TCP,root,AUTH_FAILURE,FAILED,401,Failed password for invalid user root',
      '2026-11-21T02:11:09Z,185.220.101.45,10.0.1.12,22,TCP,admin,AUTH_FAILURE,FAILED,401,Failed password for admin via sshd',
      '2026-11-21T02:11:12Z,185.220.101.45,10.0.1.12,22,TCP,ubuntu,AUTH_FAILURE,FAILED,401,Failed password for ubuntu via sshd',
      '2026-11-21T02:11:16Z,185.220.101.45,10.0.1.12,22,TCP,postgres,AUTH_FAILURE,FAILED,401,Failed password for postgres via sshd',
      '2026-11-21T02:11:20Z,185.220.101.45,10.0.1.12,22,TCP,ops_admin,AUTH_FAILURE,FAILED,401,Failed password for ops_admin via sshd',
      '2026-11-21T02:14:40Z,185.220.101.45,10.0.1.12,22,TCP,ops_admin,AUTH_EVENT,ALLOW,200,Accepted password for ops_admin from external IP during off-hours',
      '2026-11-21T02:16:05Z,185.220.101.45,10.0.1.12,22,TCP,ops_admin,PRIVILEGE_ACTION,DENIED,403,sudo attempted unauthorized read of /etc/shadow and /etc/sudoers',
      '2026-11-21T02:17:30Z,185.220.101.45,10.0.1.12,4444,TCP,ops_admin,MALWARE_SIGNAL,BLOCKED,403,Blocked outbound reverse_shell /dev/tcp c2_beacon via curl | sh',
      '2026-11-21T10:05:00Z,10.0.3.41,10.0.1.10,443,TCP,sara.miller,HTTP_ACCESS,ALLOW,200,Routine telemetry check completed',
      '2026-11-21T10:12:00Z,172.16.4.19,10.0.1.14,5432,TCP,svc-backup,DB_QUERY,ALLOW,200,Nightly snapshot verification succeeded',
    ].join('\n'),
  },
  firewall_portscan_json: {
    name: 'Firewall Reconnaissance & Malware C2 (JSON)',
    filename: 'sample_firewall_events.json',
    format: 'json',
    description: '14 structured JSON firewall and EDR records showing multi-port scanning from 198.51.100.77 and C2 beacon activity from 45.133.1.88.',
    content: JSON.stringify(
      [
        { timestamp: '2026-11-21T11:00:10Z', sourceIp: '10.0.2.15', destinationIp: '10.0.1.10', destinationPort: 443, protocol: 'TCP', username: 'alice.chen', eventType: 'FIREWALL', action: 'ALLOW', statusCode: 200, message: 'HTTPS client connection permitted' },
        { timestamp: '2026-11-21T11:02:01Z', sourceIp: '198.51.100.77', destinationIp: '10.0.1.15', destinationPort: 21, protocol: 'TCP', username: 'unknown', eventType: 'PORT_PROBE', action: 'DENIED', statusCode: 403, message: 'SYN scan probe blocked on FTP port 21' },
        { timestamp: '2026-11-21T11:02:02Z', sourceIp: '198.51.100.77', destinationIp: '10.0.1.15', destinationPort: 22, protocol: 'TCP', username: 'unknown', eventType: 'PORT_PROBE', action: 'DENIED', statusCode: 403, message: 'SYN scan probe blocked on SSH port 22' },
        { timestamp: '2026-11-21T11:02:03Z', sourceIp: '198.51.100.77', destinationIp: '10.0.1.15', destinationPort: 23, protocol: 'TCP', username: 'unknown', eventType: 'PORT_PROBE', action: 'DENIED', statusCode: 403, message: 'SYN scan probe blocked on Telnet port 23' },
        { timestamp: '2026-11-21T11:02:04Z', sourceIp: '198.51.100.77', destinationIp: '10.0.1.15', destinationPort: 445, protocol: 'TCP', username: 'unknown', eventType: 'PORT_PROBE', action: 'DENIED', statusCode: 403, message: 'SYN scan probe blocked on SMB port 445' },
        { timestamp: '2026-11-21T11:02:05Z', sourceIp: '198.51.100.77', destinationIp: '10.0.1.15', destinationPort: 3389, protocol: 'TCP', username: 'unknown', eventType: 'PORT_PROBE', action: 'DENIED', statusCode: 403, message: 'SYN scan probe blocked on RDP port 3389' },
        { timestamp: '2026-11-21T11:02:06Z', sourceIp: '198.51.100.77', destinationIp: '10.0.1.15', destinationPort: 8080, protocol: 'TCP', username: 'unknown', eventType: 'PORT_PROBE', action: 'DENIED', statusCode: 403, message: 'SYN scan probe blocked on HTTP-alt port 8080' },
        { timestamp: '2026-11-21T03:45:12Z', sourceIp: '45.133.1.88', destinationIp: '10.0.1.30', destinationPort: 4444, protocol: 'TCP', username: 'svc-web', eventType: 'MALWARE_SIGNAL', action: 'BLOCKED', statusCode: 403, message: 'Outbound c2_beacon detected with powershell -enc encoded payload' },
        { timestamp: '2026-11-21T03:46:18Z', sourceIp: '45.133.1.88', destinationIp: '10.0.1.30', destinationPort: 1337, protocol: 'TCP', username: 'svc-web', eventType: 'MALWARE_SIGNAL', action: 'BLOCKED', statusCode: 403, message: 'Blocked mimikatz credential memory dump attempt' },
        { timestamp: '2026-11-21T11:15:00Z', sourceIp: '192.168.10.45', destinationIp: '10.0.1.10', destinationPort: 443, protocol: 'TCP', username: 'sara.miller', eventType: 'FIREWALL', action: 'ALLOW', statusCode: 200, message: 'Routine API health check' },
      ],
      null,
      2
    ),
  },
  ssh_privilege_txt: {
    name: 'Linux SSHD & Sudo Syslog (TXT)',
    filename: 'sample_ssh_syslog.txt',
    format: 'txt',
    description: '12 raw syslog lines demonstrating unstructured TXT log parsing for SSH failures, RDP probes, and sudo privilege escalation.',
    content: [
      '2026-11-21T01:22:10Z srv-auth-01 sshd[4412]: Failed password for invalid user oracle from 91.240.118.14 port 22 ssh2',
      '2026-11-21T01:22:13Z srv-auth-01 sshd[4412]: Failed password for invalid user admin from 91.240.118.14 port 22 ssh2',
      '2026-11-21T01:22:16Z srv-auth-01 sshd[4412]: Failed password for invalid user deploy from 91.240.118.14 port 22 ssh2',
      '2026-11-21T01:22:19Z srv-auth-01 sshd[4412]: Failed password for root from 91.240.118.14 port 22 ssh2',
      '2026-11-21T01:22:22Z srv-auth-01 sshd[4412]: Failed password for root from 91.240.118.14 port 22 ssh2',
      '2026-11-21T01:24:05Z srv-auth-01 sudo: www-data : user NOT in sudoers ; COMMAND=/bin/chmod +s /bin/bash from 91.240.118.14',
      '2026-11-21T09:30:11Z srv-web-02 nginx: Accepted https request for alice.chen from 10.0.2.15 port 443',
      '2026-11-21T09:35:40Z srv-db-01 postgres: Authorized backup connection for svc-backup from 172.16.4.19 port 5432',
    ].join('\n'),
  },
};
