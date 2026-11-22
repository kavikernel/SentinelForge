import crypto from 'node:crypto';
import type {
  AttackSequence,
  AttackStage,
  FeatureContribution,
  MitreMapping,
  SecurityEvent,
  SensitivityConfig,
  Severity,
  ThreatAlert,
  ThreatCategory,
} from '../src/shared/types.ts';
import {
  extractEventFeatures,
  FEATURE_METADATA,
  featuresToVector,
  transformWithScaler,
} from './features.ts';
import type { TrainedMLPipeline } from './mlEngine.ts';
import type { ParsedRawEvent } from './parsers.ts';

const MITRE_CATALOG: Record<Exclude<ThreatCategory, 'Benign'>, MitreMapping> = {
  'Brute Force': {
    tacticId: 'TA0006',
    tacticName: 'Credential Access',
    techniqueId: 'T1110.001',
    techniqueName: 'Brute Force: Password Guessing',
    url: 'https://attack.mitre.org/techniques/T1110/001/',
  },
  'Port Scanning': {
    tacticId: 'TA0043',
    tacticName: 'Reconnaissance',
    techniqueId: 'T1046',
    techniqueName: 'Network Service Discovery',
    url: 'https://attack.mitre.org/techniques/T1046/',
  },
  'Suspicious Authentication': {
    tacticId: 'TA0001',
    tacticName: 'Initial Access',
    techniqueId: 'T1078',
    techniqueName: 'Valid Accounts',
    url: 'https://attack.mitre.org/techniques/T1078/',
  },
  'Privilege Escalation': {
    tacticId: 'TA0004',
    tacticName: 'Privilege Escalation',
    techniqueId: 'T1548',
    techniqueName: 'Abuse Elevation Control Mechanism',
    url: 'https://attack.mitre.org/techniques/T1548/',
  },
  'Malware Indicators': {
    tacticId: 'TA0002',
    tacticName: 'Execution',
    techniqueId: 'T1059',
    techniqueName: 'Command and Scripting Interpreter',
    url: 'https://attack.mitre.org/techniques/T1059/',
  },
  'Unusual Network Activity': {
    tacticId: 'TA0011',
    tacticName: 'Command and Control',
    techniqueId: 'T1071',
    techniqueName: 'Application Layer Protocol',
    url: 'https://attack.mitre.org/techniques/T1071/',
  },
  'Other Suspicious Behavior': {
    tacticId: 'TA0007',
    tacticName: 'Discovery',
    techniqueId: 'T1082',
    techniqueName: 'System Information Discovery',
    url: 'https://attack.mitre.org/techniques/T1082/',
  },
};

const PLAYBOOK_CATALOG: Record<Exclude<ThreatCategory, 'Benign'>, string[]> = {
  'Brute Force': [
    'Temporarily rate-limit or block the offending source IP at the perimeter firewall or WAF.',
    'Enforce multi-factor authentication (MFA) and account lockout thresholds on SSH/RDP/web portals.',
    'Verify whether any authentication attempt from this source succeeded immediately after the burst.',
    'Rotate credentials for targeted accounts and inspect active sessions.',
  ],
  'Port Scanning': [
    'Block reconnaissance source IP at ingress ACLs and verify exposed service inventory.',
    'Confirm unnecessary ports and legacy administrative interfaces are closed or restricted to VPN.',
    'Correlate source IP with subsequent authentication or exploitation events across target hosts.',
  ],
  'Suspicious Authentication': [
    'Validate login legitimacy with the account owner out-of-band (off-hours or external IP anomaly).',
    'Revoke active session tokens and enforce step-up MFA verification.',
    'Audit recent IAM, SSH key, or password modifications performed by the authenticated principal.',
  ],
  'Privilege Escalation': [
    'Isolate the affected host from sensitive internal subnets pending forensic verification.',
    'Audit `/etc/sudoers`, SUID binaries, scheduled tasks, and recent privilege assignment changes.',
    'Terminate unauthorized elevated processes and rotate privileged administrative credentials.',
  ],
  'Malware Indicators': [
    'Quarantine the endpoint immediately to prevent lateral propagation or C2 beaconing.',
    'Capture volatile process memory, command history, and SHA-256 hashes of suspicious payloads.',
    'Block outbound C2 destination IPs/ports at egress proxy and firewall layers.',
    'Run verified offline endpoint antivirus/YARA inspection on affected directories.',
  ],
  'Unusual Network Activity': [
    'Inspect egress flow logs and DNS queries associated with the anomalous host and destination port.',
    'Apply temporary egress filtering on non-standard ports (e.g., 4444, 1337, 6667, 31337).',
    'Verify whether authorized scheduled backups or maintenance jobs explain the traffic spike.',
  ],
  'Other Suspicious Behavior': [
    'Preserve raw log records and correlate surrounding events for the involved host and user.',
    'Increase audit verbosity on the targeted host and monitor for follow-on lateral movement.',
  ],
};

function severityRank(s: Severity): number {
  if (s === 'Critical') return 4;
  if (s === 'High') return 3;
  if (s === 'Medium') return 2;
  return 1;
}

function classifyCategory(ev: SecurityEvent, ruleTriggers: string[]): Exclude<ThreatCategory, 'Benign'> {
  const f = ev.features;
  const text = `${ev.eventType} ${ev.action} ${ev.message}`.toLowerCase();

  if (f.malwareKeywordScore > 0 || ev.destinationPort === 4444 || ev.destinationPort === 1337 || ev.destinationPort === 31337) {
    return 'Malware Indicators';
  }
  if (f.privilegeKeywordScore > 0 || text.includes('sudo') || text.includes('privilege') || text.includes('root')) {
    return 'Privilege Escalation';
  }
  if (
    f.isFailureStatus === 1 &&
    (ruleTriggers.some((t) => t.includes('Brute-force')) || f.failedAuthCountIp >= 5)
  ) {
    return 'Brute Force';
  }
  if (ruleTriggers.some((t) => t.includes('Port scan')) || f.distinctPortsIp >= 4) {
    return 'Port Scanning';
  }
  if (
    text.includes('login') ||
    text.includes('auth') ||
    text.includes('ssh') ||
    f.failedAuthCountIp >= 2 ||
    (f.isOffHours === 1 && f.isPublicSourceIp === 1)
  ) {
    return 'Suspicious Authentication';
  }
  if (f.suspiciousPortScore > 0 || f.interArrivalZScore >= 1.8 || f.ipEventBurstCount >= 5) {
    return 'Unusual Network Activity';
  }
  return 'Other Suspicious Behavior';
}

function computeSeverity(category: Exclude<ThreatCategory, 'Benign'>, ensembleScore: number, ruleScore: number): Severity {
  if (
    (category === 'Malware Indicators' || category === 'Privilege Escalation') &&
    (ensembleScore >= 0.72 || ruleScore >= 0.75)
  ) {
    return 'Critical';
  }
  if (ensembleScore >= 0.85 || ruleScore >= 0.9) return 'Critical';
  if (ensembleScore >= 0.68 || category === 'Brute Force' && ruleScore >= 0.65) return 'High';
  if (ensembleScore >= 0.5) return 'Medium';
  return 'Low';
}

export function analyzeEventsWithEngine(
  rawEvents: ParsedRawEvent[],
  sourceFile: string,
  isDemoData: boolean,
  pipeline: TrainedMLPipeline,
  sensitivity: SensitivityConfig,
  datasetMeta?: { datasetKey?: string; contentHash?: string }
): { events: SecurityEvent[]; alerts: ThreatAlert[]; sequences: AttackSequence[] } {
  const canonicalKey =
    datasetMeta?.datasetKey ?? sourceFile.replace(/\s*\(demo\)\s*$/i, '').trim().toLowerCase();
  const extracted = extractEventFeatures(rawEvents);
  const events: SecurityEvent[] = rawEvents.map((raw, idx) => ({
    id: `evt-${crypto.createHash('sha1').update(`${canonicalKey}-${idx}-${raw.timestamp}-${raw.sourceIp}-${raw.rawLine}`).digest('hex').slice(0, 12)}`,
    timestamp: raw.timestamp,
    sourceIp: raw.sourceIp,
    destinationIp: raw.destinationIp,
    destinationPort: raw.destinationPort,
    protocol: raw.protocol,
    username: raw.username,
    eventType: raw.eventType,
    action: raw.action,
    statusCode: raw.statusCode,
    message: raw.message,
    rawLine: raw.rawLine,
    sourceFile,
    datasetKey: canonicalKey,
    contentHash: datasetMeta?.contentHash,
    isDemoData,
    groundTruthLabel: raw.groundTruthLabel,
    features: extracted[idx],
  }));

  const rawVectors = events.map((e) => featuresToVector(e.features));
  const scaledVectors = transformWithScaler(rawVectors, pipeline.scaler);

  const candidateDetections: Array<{
    event: SecurityEvent;
    category: Exclude<ThreatCategory, 'Benign'>;
    ruleScore: number;
    ruleTriggers: string[];
    mlProbability: number;
    anomalyScore: number;
    avgPathLength: number;
    ensembleScore: number;
    severity: Severity;
    reasons: string[];
    contributions: FeatureContribution[];
  }> = [];

  events.forEach((ev, idx) => {
    const f = ev.features;
    const ruleTriggers: string[] = [];
    let ruleScore = 0;

    if (f.isFailureStatus === 1 && f.failedAuthCountIp >= sensitivity.bruteForceThreshold) {
      ruleTriggers.push(`Brute-force pattern: ${f.failedAuthCountIp} failed authentication events from ${ev.sourceIp}`);
      ruleScore += 0.45;
    } else if (f.isFailureStatus === 1 && f.failedAuthCountIp >= 2) {
      ruleTriggers.push(`Repeated failed authentication (${f.failedAuthCountIp} failures from ${ev.sourceIp})`);
      ruleScore += 0.25;
    } else if (
      f.isFailureStatus === 0 &&
      f.failedAuthCountIp >= sensitivity.bruteForceThreshold &&
      (ev.eventType.toUpperCase().includes('AUTH') || ev.message.toLowerCase().includes('password') || ev.message.toLowerCase().includes('login'))
    ) {
      ruleTriggers.push(`Suspicious authentication success from ${ev.sourceIp} immediately following ${f.failedAuthCountIp} failed attempts`);
      ruleScore += 0.45;
    }

    if (f.distinctPortsIp >= sensitivity.portScanThreshold) {
      ruleTriggers.push(`Port scan signature: ${f.distinctPortsIp} distinct destination ports probed by ${ev.sourceIp}`);
      ruleScore += 0.48;
    }

    if (f.privilegeKeywordScore > 0) {
      ruleTriggers.push(`Privilege escalation indicator detected in command/event message`);
      ruleScore += 0.42 + f.privilegeKeywordScore * 0.25;
    }

    if (f.malwareKeywordScore > 0) {
      ruleTriggers.push(`Malware or suspicious payload execution pattern matched in log payload`);
      ruleScore += 0.5 + f.malwareKeywordScore * 0.3;
    }

    if (f.suspiciousPortScore >= 0.6) {
      ruleTriggers.push(`Traffic targeting high-risk service port ${ev.destinationPort}/${ev.protocol}`);
      ruleScore += 0.22 * f.suspiciousPortScore;
    }

    if (f.isOffHours === 1 && f.isPublicSourceIp === 1) {
      ruleTriggers.push(`Unusual off-hours access attempt (${new Date(ev.timestamp).toISOString().slice(11, 16)} UTC) from external IP`);
      ruleScore += 0.24;
    }

    if (f.interArrivalZScore >= 1.6) {
      ruleTriggers.push(`Statistical frequency anomaly (event burst Z-score ${f.interArrivalZScore.toFixed(2)})`);
      ruleScore += 0.2;
    }

    ruleScore = Math.min(1, Number(ruleScore.toFixed(4)));

    const scaledPt = scaledVectors[idx];
    const { anomalyScore, avgPathLength } = pipeline.isolationForest.scorePoint(scaledPt);
    const mlProbability = pipeline.logisticRegression.predictProbability(scaledPt);
    const rawContribs = pipeline.logisticRegression.featureContributions(scaledPt);

    const ensembleScore = Number(
      Math.min(1, 0.35 * ruleScore + 0.4 * mlProbability + 0.25 * anomalyScore).toFixed(4)
    );

    const triggered =
      ruleScore >= sensitivity.ruleAlertThreshold ||
      ensembleScore >= sensitivity.ruleAlertThreshold ||
      (mlProbability >= sensitivity.mlProbabilityThreshold && anomalyScore >= 0.5) ||
      (anomalyScore >= sensitivity.anomalyThreshold && mlProbability >= 0.35);

    if (!triggered) return;

    const category = classifyCategory(ev, ruleTriggers);
    const severity = computeSeverity(category, ensembleScore, ruleScore);

    const contributions: FeatureContribution[] = FEATURE_METADATA.map((meta, j) => {
      const weight = Number((pipeline.logisticRegression.weights[j] ?? 0).toFixed(4));
      const contrib = rawContribs[j] ?? 0;
      return {
        featureName: meta.key,
        label: meta.label,
        rawValue: rawVectors[idx][j],
        normalizedValue: scaledPt[j],
        weight,
        contribution: contrib,
        direction: contrib >= 0 ? ('threat' as const) : ('benign' as const),
      };
    }).sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution));

    const reasons: string[] = [...ruleTriggers];
    reasons.push(
      `Supervised Logistic Regression assigned ${(mlProbability * 100).toFixed(1)}% threat probability.`
    );
    reasons.push(
      `Isolation Forest anomaly score ${(anomalyScore * 100).toFixed(1)}% (avg tree path length ${avgPathLength.toFixed(2)}).`
    );
    const topPos = contributions.find((c) => c.contribution > 0.05);
    if (topPos) {
      reasons.push(
        `Primary ML driver: ${topPos.label} (observed ${topPos.rawValue}, contribution +${topPos.contribution.toFixed(2)}).`
      );
    }

    candidateDetections.push({
      event: ev,
      category,
      ruleScore,
      ruleTriggers,
      mlProbability,
      anomalyScore,
      avgPathLength,
      ensembleScore,
      severity,
      reasons,
      contributions,
    });
  });

  // Group repetitive identical-category bursts from the same source IP within the batch so alerts stay actionable
  const grouped = new Map<string, typeof candidateDetections>();
  for (const det of candidateDetections) {
    const key = `${det.event.sourceIp}::${det.category}`;
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key)!.push(det);
  }

  const alerts: ThreatAlert[] = [];
  for (const [, group] of grouped) {
    group.sort((a, b) => b.ensembleScore - a.ensembleScore);
    const lead = group[0];
    const mitre = MITRE_CATALOG[lead.category];
    const recommendations = PLAYBOOK_CATALOG[lead.category];
    const latestTs = group.reduce(
      (max, g) => (g.event.timestamp > max ? g.event.timestamp : max),
      lead.event.timestamp
    );

    const titleMap: Record<Exclude<ThreatCategory, 'Benign'>, string> = {
      'Brute Force': `Credential Brute-Force Burst from ${lead.event.sourceIp}`,
      'Port Scanning': `Multi-Port Reconnaissance Scan from ${lead.event.sourceIp}`,
      'Suspicious Authentication': `Suspicious Authentication Anomaly (${lead.event.username})`,
      'Privilege Escalation': `Privilege Escalation Indicator on ${lead.event.destinationIp}`,
      'Malware Indicators': `Malicious Payload / C2 Indicator from ${lead.event.sourceIp}`,
      'Unusual Network Activity': `Anomalous Network Activity via Port ${lead.event.destinationPort}`,
      'Other Suspicious Behavior': `Anomalous Security Event from ${lead.event.sourceIp}`,
    };

    const alertId = `alt-${crypto
      .createHash('sha1')
      .update(`${canonicalKey}-${lead.event.sourceIp}-${lead.category}-${latestTs}`)
      .digest('hex')
      .slice(0, 10)}`;

    alerts.push({
      id: alertId,
      eventIds: group.map((g) => g.event.id),
      primaryEventId: lead.event.id,
      timestamp: latestTs,
      sourceIp: lead.event.sourceIp,
      destinationIp: lead.event.destinationIp,
      username: lead.event.username,
      title: titleMap[lead.category],
      description: `${group.length} correlated ${lead.category.toLowerCase()} event(s) targeting ${lead.event.destinationIp} (user: ${lead.event.username}). ${lead.event.message}`,
      category: lead.category,
      severity: lead.severity,
      confidence: Number((lead.ensembleScore * 100).toFixed(1)),
      ruleScore: lead.ruleScore,
      mlProbability: lead.mlProbability,
      anomalyScore: lead.anomalyScore,
      status: 'open',
      analystFeedback: 'unreviewed',
      mitre,
      xai: {
        reasons: lead.reasons,
        ruleTriggers: lead.ruleTriggers,
        isolationForestScore: lead.anomalyScore,
        isolationAvgPathLength: lead.avgPathLength,
        logisticRegressionProb: lead.mlProbability,
        statisticalZScore: lead.event.features.interArrivalZScore,
        ensembleScore: lead.ensembleScore,
        featureContributions: lead.contributions,
      },
      recommendations,
      isDemoData,
      datasetKey: canonicalKey,
      contentHash: datasetMeta?.contentHash,
    });
  }

  alerts.sort((a, b) => {
    const sevDiff = severityRank(b.severity) - severityRank(a.severity);
    if (sevDiff !== 0) return sevDiff;
    return b.timestamp.localeCompare(a.timestamp);
  });

  const sequences = correlateAttackSequences(alerts);
  return { events, alerts, sequences };
}

export function correlateAttackSequences(alerts: ThreatAlert[]): AttackSequence[] {
  const byIp = new Map<string, ThreatAlert[]>();
  for (const alert of alerts) {
    if (!byIp.has(alert.sourceIp)) byIp.set(alert.sourceIp, []);
    byIp.get(alert.sourceIp)!.push(alert);
  }

  const sequences: AttackSequence[] = [];
  for (const [sourceIp, ipAlerts] of byIp) {
    if (ipAlerts.length < 2) continue;
    const sorted = [...ipAlerts].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    const distinctCategories = new Set(sorted.map((a) => a.category));
    if (distinctCategories.size < 2 && sorted.length < 2) continue;

    const stages: AttackStage[] = sorted.map((al, idx) => ({
      order: idx + 1,
      timestamp: al.timestamp,
      alertId: al.id,
      category: al.category,
      mitreTactic: `${al.mitre.tacticId} ${al.mitre.tacticName}`,
      mitreTechnique: `${al.mitre.techniqueId} ${al.mitre.techniqueName}`,
      summary: al.title,
      severity: al.severity,
    }));

    const maxSev = sorted.reduce<Severity>(
      (acc, cur) => (severityRank(cur.severity) > severityRank(acc) ? cur.severity : acc),
      'Low'
    );
    const avgConf = sorted.reduce((acc, cur) => acc + cur.confidence, 0) / sorted.length;
    const riskScore = Math.min(99, Math.round(avgConf * 0.75 + distinctCategories.size * 10));
    const targetUsers = Array.from(new Set(sorted.map((a) => a.username).filter((u) => u !== 'unknown')));

    const chainSummary = stages.map((s) => s.category).join(' -> ');

    sequences.push({
      id: `seq-${crypto.createHash('sha1').update(`${sourceIp}-${sorted[0].timestamp}-${stages.length}`).digest('hex').slice(0, 10)}`,
      sourceIp,
      targetUsers: targetUsers.length > 0 ? targetUsers : ['system'],
      startTime: sorted[0].timestamp,
      endTime: sorted[sorted.length - 1].timestamp,
      stageCount: stages.length,
      overallSeverity: maxSev,
      riskScore,
      narrative: `Multi-stage sequence detected from ${sourceIp}: ${chainSummary}. Correlated across ${stages.length} alert stage(s).`,
      stages,
      isDemoData: sorted.every((a) => a.isDemoData),
    });
  }

  sequences.sort((a, b) => b.riskScore - a.riskScore);
  return sequences;
}
