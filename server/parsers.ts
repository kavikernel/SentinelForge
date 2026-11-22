import type { DatasetValidationError, EventFeatures } from '../src/shared/types.ts';

export interface ParsedRawEvent {
  timestamp: string;
  sourceIp: string;
  destinationIp: string;
  destinationPort: number;
  protocol: string;
  username: string;
  eventType: string;
  action: string;
  statusCode: number;
  message: string;
  rawLine: string;
  groundTruthLabel?: 0 | 1;
}

export interface ParseResult {
  format: 'csv' | 'json' | 'txt';
  totalLines: number;
  parsed: ParsedRawEvent[];
  errors: DatasetValidationError[];
}

const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
const IPV6_REGEX = /^(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}$/;

export function isValidIp(ip: string): boolean {
  const trimmed = ip.trim();
  return IPV4_REGEX.test(trimmed) || IPV6_REGEX.test(trimmed);
}

function normalizeTimestamp(raw: unknown): string | null {
  if (typeof raw !== 'string' && typeof raw !== 'number') return null;
  const s = String(raw).trim();
  if (!s || /^\d+$/.test(s)) return null;
  const parsed = new Date(s);
  if (!Number.isNaN(parsed.getTime())) {
    return parsed.toISOString();
  }
  // Handle syslog format without year e.g. "Nov 21 03:14:22"
  const syslogMatch = /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})$/.exec(s);
  if (syslogMatch) {
    const year = new Date().getUTCFullYear();
    const candidate = new Date(`${syslogMatch[1]} ${syslogMatch[2]} ${year} ${syslogMatch[3]} UTC`);
    if (!Number.isNaN(candidate.getTime())) {
      return candidate.toISOString();
    }
  }
  return null;
}

function parseStrictPort(raw: unknown, fallbackIfMissing?: number): number | null {
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    return fallbackIfMissing ?? null;
  }
  const s = String(raw).trim();
  if (!/^\d+$/.test(s)) return null;
  const n = Number(s);
  if (!Number.isInteger(n) || n < 0 || n > 65535) return null;
  return n;
}

function parseStrictStatusCode(raw: unknown, fallbackIfMissing?: number): number | null {
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    return fallbackIfMissing ?? null;
  }
  const s = String(raw).trim();
  if (!/^\d+$/.test(s)) return null;
  const n = Number(s);
  if (!Number.isInteger(n) || n < 0 || n > 999) return null;
  return n;
}

function splitCsvLine(line: string): string[] {
  const result: string[] = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === ',' && !inQuotes) {
      result.push(current.trim());
      current = '';
    } else {
      current += ch;
    }
  }
  result.push(current.trim());
  return result;
}

function coerceLabel(val: unknown): 0 | 1 | undefined {
  if (val === 1 || val === '1' || val === true || String(val).toLowerCase() === 'threat' || String(val).toLowerCase() === 'malicious') {
    return 1;
  }
  if (val === 0 || val === '0' || val === false || String(val).toLowerCase() === 'benign' || String(val).toLowerCase() === 'normal') {
    return 0;
  }
  return undefined;
}

export function parseCsvLogs(content: string): ParseResult {
  const lines = content
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

  if (lines.length < 2) {
    return {
      format: 'csv',
      totalLines: lines.length,
      parsed: [],
      errors: [{ line: 1, raw: content.slice(0, 120), reason: 'CSV must include a header row and at least one data row.' }],
    };
  }

  const headers = splitCsvLine(lines[0]).map((h) => h.toLowerCase().replace(/[^a-z0-9_]/g, ''));
  const colIndex = (candidates: string[]) => headers.findIndex((h) => candidates.includes(h));

  const idxTs = colIndex(['timestamp', 'time', 'date', 'datetime', 'createdat']);
  const idxSrc = colIndex(['sourceip', 'source_ip', 'srcip', 'src_ip', 'ip', 'clientip']);
  const idxDst = colIndex(['destinationip', 'destination_ip', 'dstip', 'dst_ip', 'targetip']);
  const idxPort = colIndex(['destinationport', 'destination_port', 'port', 'dstport', 'dst_port']);
  const idxProto = colIndex(['protocol', 'proto']);
  const idxUser = colIndex(['username', 'user', 'account']);
  const idxType = colIndex(['eventtype', 'event_type', 'type', 'category']);
  const idxAction = colIndex(['action', 'status', 'outcome']);
  const idxCode = colIndex(['statuscode', 'status_code', 'code', 'httpstatus']);
  const idxMsg = colIndex(['message', 'msg', 'details', 'description', 'command']);
  const idxLabel = colIndex(['label', 'isthreat', 'is_threat', 'groundtruth']);

  if (idxTs === -1 || idxSrc === -1 || idxMsg === -1) {
    return {
      format: 'csv',
      totalLines: lines.length - 1,
      parsed: [],
      errors: [
        {
          line: 1,
          raw: lines[0].slice(0, 120),
          reason: 'Missing required CSV columns (expected timestamp, source_ip, and message headers).',
        },
      ],
    };
  }

  const parsed: ParsedRawEvent[] = [];
  const errors: DatasetValidationError[] = [];

  for (let i = 1; i < lines.length; i++) {
    const rawLine = lines[i];
    const cols = splitCsvLine(rawLine);
    if (cols.length !== headers.length) {
      errors.push({
        line: i + 1,
        raw: rawLine.slice(0, 120),
        reason: `Incomplete or malformed CSV row (expected ${headers.length} columns, found ${cols.length}).`,
      });
      continue;
    }

    const ts = normalizeTimestamp(cols[idxTs]);
    if (!ts) {
      errors.push({ line: i + 1, raw: rawLine.slice(0, 120), reason: `Invalid or missing timestamp: "${cols[idxTs]}"` });
      continue;
    }

    const sourceIp = (cols[idxSrc] ?? '').trim();
    if (!sourceIp || !isValidIp(sourceIp)) {
      errors.push({ line: i + 1, raw: rawLine.slice(0, 120), reason: `Invalid or missing source IP address: "${sourceIp}"` });
      continue;
    }

    let destinationIp = '10.0.1.10';
    if (idxDst >= 0) {
      const rawDst = (cols[idxDst] ?? '').trim();
      if (!rawDst || !isValidIp(rawDst)) {
        errors.push({ line: i + 1, raw: rawLine.slice(0, 120), reason: `Invalid or missing destination IP: "${rawDst}"` });
        continue;
      }
      destinationIp = rawDst;
    }

    const destinationPort = idxPort >= 0 ? parseStrictPort(cols[idxPort]) : 443;
    if (destinationPort === null) {
      errors.push({ line: i + 1, raw: rawLine.slice(0, 120), reason: `Invalid destination port: "${cols[idxPort]}"` });
      continue;
    }

    const statusCode = idxCode >= 0 ? parseStrictStatusCode(cols[idxCode]) : 200;
    if (statusCode === null) {
      errors.push({ line: i + 1, raw: rawLine.slice(0, 120), reason: `Invalid status code: "${cols[idxCode]}"` });
      continue;
    }

    const message = (cols[idxMsg] ?? '').trim();
    if (!message) {
      errors.push({ line: i + 1, raw: rawLine.slice(0, 120), reason: 'Missing event message.' });
      continue;
    }

    parsed.push({
      timestamp: ts,
      sourceIp,
      destinationIp,
      destinationPort,
      protocol: (idxProto >= 0 ? cols[idxProto] : '') || 'TCP',
      username: (idxUser >= 0 ? cols[idxUser] : '') || 'unknown',
      eventType: (idxType >= 0 ? cols[idxType] : '') || 'NETWORK_EVENT',
      action: ((idxAction >= 0 ? cols[idxAction] : '') || 'ALLOW').toUpperCase(),
      statusCode,
      message,
      rawLine,
      groundTruthLabel: idxLabel >= 0 ? coerceLabel(cols[idxLabel]) : undefined,
    });
  }

  return { format: 'csv', totalLines: lines.length - 1, parsed, errors };
}

export function parseJsonLogs(content: string): ParseResult {
  let rawData: unknown;
  try {
    rawData = JSON.parse(content);
  } catch (err) {
    return {
      format: 'json',
      totalLines: 1,
      parsed: [],
      errors: [
        {
          line: 1,
          raw: content.slice(0, 120),
          reason: `Malformed JSON: ${err instanceof Error ? err.message : 'Unable to parse JSON'}`,
        },
      ],
    };
  }

  const records = Array.isArray(rawData)
    ? rawData
    : typeof rawData === 'object' && rawData !== null && Array.isArray((rawData as Record<string, unknown>).events)
      ? ((rawData as Record<string, unknown>).events as unknown[])
      : typeof rawData === 'object' && rawData !== null && Array.isArray((rawData as Record<string, unknown>).logs)
        ? ((rawData as Record<string, unknown>).logs as unknown[])
        : null;

  if (!records || records.length === 0) {
    return {
      format: 'json',
      totalLines: 0,
      parsed: [],
      errors: [{ line: 1, raw: content.slice(0, 120), reason: 'JSON must be a non-empty array of log objects or { events: [...] }.' }],
    };
  }

  const parsed: ParsedRawEvent[] = [];
  const errors: DatasetValidationError[] = [];

  records.forEach((item, index) => {
    if (typeof item !== 'object' || item === null || Array.isArray(item)) {
      errors.push({ line: index + 1, raw: String(item).slice(0, 120), reason: 'Entry is not a JSON object.' });
      return;
    }
    const obj = item as Record<string, unknown>;
    const rawPreview = JSON.stringify(obj).slice(0, 120);

    const tsRaw = obj.timestamp ?? obj.time ?? obj.date;
    const ts = normalizeTimestamp(tsRaw);
    if (!ts) {
      errors.push({
        line: index + 1,
        raw: rawPreview,
        reason: `Missing or invalid timestamp: "${String(tsRaw ?? '')}"`,
      });
      return;
    }

    const sourceIp = String(obj.sourceIp ?? obj.source_ip ?? obj.src_ip ?? obj.ip ?? '').trim();
    if (!sourceIp || !isValidIp(sourceIp)) {
      errors.push({
        line: index + 1,
        raw: rawPreview,
        reason: `Missing or invalid sourceIp: "${sourceIp}"`,
      });
      return;
    }

    const dstRaw = obj.destinationIp ?? obj.destination_ip ?? obj.dst_ip;
    let destinationIp = '10.0.1.10';
    if (dstRaw !== undefined && dstRaw !== null && String(dstRaw).trim() !== '') {
      const dstStr = String(dstRaw).trim();
      if (!isValidIp(dstStr)) {
        errors.push({
          line: index + 1,
          raw: rawPreview,
          reason: `Invalid destinationIp: "${dstStr}"`,
        });
        return;
      }
      destinationIp = dstStr;
    }

    const destinationPort = parseStrictPort(obj.destinationPort ?? obj.destination_port ?? obj.port, 443);
    if (destinationPort === null) {
      errors.push({
        line: index + 1,
        raw: rawPreview,
        reason: `Invalid destinationPort: "${String(obj.destinationPort ?? obj.destination_port ?? obj.port)}"`,
      });
      return;
    }

    const statusCode = parseStrictStatusCode(obj.statusCode ?? obj.status_code ?? obj.code, 200);
    if (statusCode === null) {
      errors.push({
        line: index + 1,
        raw: rawPreview,
        reason: `Invalid statusCode: "${String(obj.statusCode ?? obj.status_code ?? obj.code)}"`,
      });
      return;
    }

    const message = String(obj.message ?? obj.msg ?? obj.details ?? '').trim();
    if (!message) {
      errors.push({
        line: index + 1,
        raw: rawPreview,
        reason: 'Missing required message/details field.',
      });
      return;
    }

    parsed.push({
      timestamp: ts,
      sourceIp,
      destinationIp,
      destinationPort,
      protocol: String(obj.protocol ?? 'TCP').toUpperCase(),
      username: String(obj.username ?? obj.user ?? 'unknown'),
      eventType: String(obj.eventType ?? obj.event_type ?? obj.type ?? 'SECURITY_EVENT'),
      action: String(obj.action ?? obj.outcome ?? 'LOGGED').toUpperCase(),
      statusCode,
      message,
      rawLine: JSON.stringify(obj),
      groundTruthLabel: coerceLabel(obj.label ?? obj.isThreat ?? obj.is_threat),
    });
  });

  return { format: 'json', totalLines: records.length, parsed, errors };
}

export function parseTxtLogs(content: string): ParseResult {
  const lines = content
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith('#'));

  if (lines.length === 0) {
    return {
      format: 'txt',
      totalLines: 0,
      parsed: [],
      errors: [{ line: 1, raw: '', reason: 'Text log file contains no log lines.' }],
    };
  }

  const parsed: ParsedRawEvent[] = [];
  const errors: DatasetValidationError[] = [];

  const ipExtractRegex = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
  const isoPrefixRegex = /^(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+/;
  const syslogPrefixRegex = /^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s*(.*)$/;
  const portMatchRegex = /(?:port|dpt|dport)[=:\s]+(\d{1,5})/i;
  const userMatchRegex = /(?:user|for|account|sudo:\s*)([a-zA-Z0-9._-]{2,32})/i;

  lines.forEach((line, idx) => {
    let timestamp: string | null = null;
    let message = '';
    const isoMatch = isoPrefixRegex.exec(line);
    const sysMatch = syslogPrefixRegex.exec(line);
    if (isoMatch) {
      timestamp = normalizeTimestamp(isoMatch[1]);
      message = line.slice(isoMatch[0].length).trim();
    } else if (sysMatch) {
      timestamp = normalizeTimestamp(sysMatch[1]);
      message = `${sysMatch[3]}: ${sysMatch[4]}`.trim();
    }

    if (!timestamp) {
      errors.push({
        line: idx + 1,
        raw: line.slice(0, 120),
        reason: 'Missing or invalid ISO-8601 / syslog timestamp prefix.',
      });
      return;
    }

    if (!message || message.length < 4) {
      errors.push({
        line: idx + 1,
        raw: line.slice(0, 120),
        reason: 'Incomplete syslog line (missing event message).',
      });
      return;
    }

    const ips = line.match(ipExtractRegex);
    if (!ips || ips.length === 0) {
      errors.push({ line: idx + 1, raw: line.slice(0, 120), reason: 'No valid IPv4 address found in log line.' });
      return;
    }

    const lower = line.toLowerCase();
    const portMatch = portMatchRegex.exec(line);
    const parsedPort = portMatch ? parseStrictPort(portMatch[1]) : null;
    if (portMatch && parsedPort === null) {
      errors.push({ line: idx + 1, raw: line.slice(0, 120), reason: `Invalid port in log line: "${portMatch[1]}"` });
      return;
    }
    const port = parsedPort ?? (lower.includes('sshd') ? 22 : lower.includes('https') ? 443 : 80);

    let username = 'unknown';
    const invalidUserMatch = /invalid user\s+(\S+)/i.exec(line);
    const forUserMatch = /for\s+(?:invalid user\s+)?([a-zA-Z0-9._-]+)\s+from/i.exec(line);
    const sudoUserMatch = /sudo:\s*([a-zA-Z0-9._-]+)\s*:/i.exec(line);
    if (invalidUserMatch) username = invalidUserMatch[1];
    else if (forUserMatch) username = forUserMatch[1];
    else if (sudoUserMatch) username = sudoUserMatch[1];
    else {
      const genericUser = userMatchRegex.exec(line);
      if (genericUser && !['from', 'port', 'invalid'].includes(genericUser[1].toLowerCase())) {
        username = genericUser[1];
      }
    }

    const isFail =
      lower.includes('failed') ||
      lower.includes('denied') ||
      lower.includes('blocked') ||
      lower.includes('invalid') ||
      lower.includes('unauthorized') ||
      lower.includes('refused');

    const eventType = lower.includes('sudo') || lower.includes('privilege')
      ? 'PRIVILEGE_ACTION'
      : lower.includes('scan') || lower.includes('syn')
        ? 'PORT_PROBE'
        : lower.includes('ssh') || lower.includes('login') || lower.includes('auth')
          ? 'AUTH_EVENT'
          : 'SYSLOG_EVENT';

    parsed.push({
      timestamp,
      sourceIp: ips[0],
      destinationIp: ips[1] ?? '10.0.1.10',
      destinationPort: port,
      protocol: lower.includes('udp') ? 'UDP' : 'TCP',
      username,
      eventType,
      action: isFail ? 'DENIED' : 'ALLOW',
      statusCode: isFail ? 401 : 200,
      message,
      rawLine: line,
    });
  });

  return { format: 'txt', totalLines: lines.length, parsed, errors };
}

export function parseSecurityLogs(filename: string, content: string, explicitFormat?: 'csv' | 'json' | 'txt'): ParseResult {
  const trimmed = content.trim();
  if (!trimmed) {
    return {
      format: explicitFormat ?? 'txt',
      totalLines: 0,
      parsed: [],
      errors: [{ line: 1, raw: '', reason: 'Uploaded file is empty.' }],
    };
  }

  const ext = filename.split('.').pop()?.toLowerCase();
  const format: 'csv' | 'json' | 'txt' =
    explicitFormat ?? (ext === 'csv' ? 'csv' : ext === 'json' ? 'json' : ext === 'txt' || ext === 'log' ? 'txt' : trimmed.startsWith('[') || trimmed.startsWith('{') ? 'json' : 'csv');

  if (format === 'json') return parseJsonLogs(trimmed);
  if (format === 'csv') return parseCsvLogs(trimmed);
  return parseTxtLogs(trimmed);
}

export function emptyFeatures(): EventFeatures {
  return {
    failedAuthCountIp: 0,
    distinctPortsIp: 1,
    ipEventBurstCount: 1,
    isOffHours: 0,
    privilegeKeywordScore: 0,
    malwareKeywordScore: 0,
    suspiciousPortScore: 0,
    isPublicSourceIp: 0,
    isFailureStatus: 0,
    interArrivalZScore: 0,
  };
}
