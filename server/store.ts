import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type {
  AttackSequence,
  AuditLogEntry,
  DatasetUploadRecord,
  ForensicCase,
  MLEvaluationReport,
  PublicUser,
  SecurityEvent,
  SensitivityConfig,
  SensitivityLevel,
  ThreatAlert,
  ThreatIntelRecord,
} from '../src/shared/types.ts';
import { createDefaultDemoUsers, type StoredDemoUser } from './auth.ts';
import { buildReproducibleLabeledDataset, SAMPLE_DATASETS } from './datasets.ts';
import { analyzeEventsWithEngine, correlateAttackSequences } from './detectionEngine.ts';
import { extractEventFeatures, featuresToVector } from './features.ts';
import { analyzeLocalIpIntel } from './intel.ts';
import { trainAndEvaluatePipeline, type TrainedMLPipeline } from './mlEngine.ts';
import { parseSecurityLogs } from './parsers.ts';

export interface PersistedStore {
  version: number;
  sensitivity: SensitivityConfig;
  splitRatio: number;
  seed: number;
  events: SecurityEvent[];
  alerts: ThreatAlert[];
  sequences: AttackSequence[];
  forensicCases: ForensicCase[];
  auditLogs: AuditLogEntry[];
  intelRecords: ThreatIntelRecord[];
  uploads: DatasetUploadRecord[];
  demoUsers: StoredDemoUser[];
  mlEvaluation: MLEvaluationReport;
}

export function getSensitivityPreset(level: SensitivityLevel): SensitivityConfig {
  if (level === 'high') {
    return {
      level: 'high',
      anomalyThreshold: 0.52,
      mlProbabilityThreshold: 0.45,
      ruleAlertThreshold: 0.35,
      bruteForceThreshold: 3,
      portScanThreshold: 3,
    };
  }
  if (level === 'low') {
    return {
      level: 'low',
      anomalyThreshold: 0.68,
      mlProbabilityThreshold: 0.68,
      ruleAlertThreshold: 0.6,
      bruteForceThreshold: 6,
      portScanThreshold: 6,
    };
  }
  return {
    level: 'balanced',
    anomalyThreshold: 0.58,
    mlProbabilityThreshold: 0.54,
    ruleAlertThreshold: 0.45,
    bruteForceThreshold: 4,
    portScanThreshold: 4,
  };
}

export function normalizeDatasetKey(filename: string): string {
  return path.basename(filename.trim()).replace(/\s*\(demo\)\s*$/i, '').trim().toLowerCase();
}

function computeContentHash(content: string): string {
  return crypto.createHash('sha256').update(content.trim()).digest('hex').slice(0, 16);
}

export class SentinelStore {
  private filePath: string;
  private state: PersistedStore;
  private pipeline: TrainedMLPipeline;

  constructor(dataDir?: string) {
    const resolvedDir = path.resolve(dataDir ?? process.env.DATA_DIR ?? path.join(process.cwd(), 'data'));
    if (!fs.existsSync(resolvedDir)) {
      fs.mkdirSync(resolvedDir, { recursive: true });
    }
    this.filePath = path.join(resolvedDir, 'sentinelforge-store.json');

    const baseDataset = buildReproducibleLabeledDataset(2026);
    this.pipeline = trainAndEvaluatePipeline(
      baseDataset.map((d) => ({ vector: d.vector, label: d.label })),
      0.75,
      2026,
      0
    );

    if (fs.existsSync(this.filePath)) {
      try {
        const raw = fs.readFileSync(this.filePath, 'utf8');
        const loaded = JSON.parse(raw) as PersistedStore;
        if (loaded && loaded.version === 2 && Array.isArray(loaded.events)) {
          this.state = loaded;
          // Retrain pipeline consistently using stored splitRatio/seed + feedback
          this.retrainPipelineInternal(loaded.splitRatio ?? 0.75, loaded.seed ?? 2026, false);
          return;
        }
      } catch {
        // Fallback to clean seed if store file is corrupted
      }
    }

    this.state = this.createInitialSeedState();
    this.save();
  }

  private createInitialSeedState(): PersistedStore {
    const sensitivity = getSensitivityPreset('balanced');
    const splitRatio = 0.75;
    const seed = 2026;

    const baseDataset = buildReproducibleLabeledDataset(seed);
    this.pipeline = trainAndEvaluatePipeline(
      baseDataset.map((d) => ({ vector: d.vector, label: d.label })),
      splitRatio,
      seed,
      0
    );

    const key1 = normalizeDatasetKey(SAMPLE_DATASETS.bruteforce_lateral_csv.filename);
    const hash1 = computeContentHash(SAMPLE_DATASETS.bruteforce_lateral_csv.content);
    const key2 = normalizeDatasetKey(SAMPLE_DATASETS.firewall_portscan_json.filename);
    const hash2 = computeContentHash(SAMPLE_DATASETS.firewall_portscan_json.content);

    const parsed1 = parseSecurityLogs(
      SAMPLE_DATASETS.bruteforce_lateral_csv.filename,
      SAMPLE_DATASETS.bruteforce_lateral_csv.content,
      'csv'
    );
    const parsed2 = parseSecurityLogs(
      SAMPLE_DATASETS.firewall_portscan_json.filename,
      SAMPLE_DATASETS.firewall_portscan_json.content,
      'json'
    );

    const res1 = analyzeEventsWithEngine(
      parsed1.parsed,
      `${SAMPLE_DATASETS.bruteforce_lateral_csv.filename} (Demo)`,
      true,
      this.pipeline,
      sensitivity,
      { datasetKey: key1, contentHash: hash1 }
    );
    const res2 = analyzeEventsWithEngine(
      parsed2.parsed,
      `${SAMPLE_DATASETS.firewall_portscan_json.filename} (Demo)`,
      true,
      this.pipeline,
      sensitivity,
      { datasetKey: key2, contentHash: hash2 }
    );

    const events = [...res1.events, ...res2.events];
    const alerts = [...res1.alerts, ...res2.alerts];

    // Pre-triage one demo alert so SOC dashboard shows realistic workflow states
    if (alerts.length > 2) {
      alerts[alerts.length - 1].status = 'acknowledged';
      alerts[alerts.length - 1].acknowledgedBy = 'analyst (Demo)';
      alerts[alerts.length - 1].acknowledgedAt = new Date(Date.now() - 1800_000).toISOString();
    }

    const sequences = correlateAttackSequences(alerts);

    const topAlert = alerts[0];
    const forensicCases: ForensicCase[] = topAlert
      ? [
          {
            id: 'fcase-demo-001',
            alertId: topAlert.id,
            title: `Forensic Investigation: ${topAlert.title}`,
            severity: topAlert.severity,
            sourceIp: topAlert.sourceIp,
            status: 'investigating',
            evidenceSha256: crypto
              .createHash('sha256')
              .update(JSON.stringify(topAlert.eventIds))
              .digest('hex'),
            evidenceSummary: `Preserved ${topAlert.eventIds.length} normalized log records and raw syslog/CSV lines for ${topAlert.sourceIp}.`,
            rawArtifacts: events
              .filter((e) => topAlert.eventIds.includes(e.id))
              .map((e) => e.rawLine)
              .slice(0, 6),
            timeline: [
              {
                timestamp: topAlert.timestamp,
                event: `Alert raised (${topAlert.category}, MITRE ${topAlert.mitre.techniqueId})`,
                actor: 'SentinelForge Detection Engine',
              },
              {
                timestamp: new Date(Date.now() - 900_000).toISOString(),
                event: 'Chain-of-custody SHA-256 evidence digest computed and locked.',
                actor: 'analyst (Demo)',
              },
            ],
            notes: [
              {
                id: 'note-demo-1',
                author: 'Maya Lin (Demo SOC Analyst)',
                authorRole: 'analyst',
                timestamp: new Date(Date.now() - 800_000).toISOString(),
                content:
                  'Synthetic demonstration case: correlated off-hours SSH credential burst with subsequent privilege escalation attempt.',
              },
            ],
            createdAt: new Date(Date.now() - 1200_000).toISOString(),
            updatedAt: new Date(Date.now() - 800_000).toISOString(),
            isDemoData: true,
          },
        ]
      : [];

    const uniqueIps = Array.from(new Set(events.map((e) => e.sourceIp)));
    const intelRecords = uniqueIps.map((ip) => analyzeLocalIpIntel(ip));

    const uploads: DatasetUploadRecord[] = [
      {
        id: 'upl-demo-1',
        filename: `${SAMPLE_DATASETS.bruteforce_lateral_csv.filename} (Demo)`,
        datasetKey: key1,
        contentHash: hash1,
        format: 'csv',
        uploadedAt: new Date(Date.now() - 3600_000).toISOString(),
        uploadedBy: 'system-seed',
        totalLines: parsed1.totalLines,
        validCount: parsed1.parsed.length,
        invalidCount: parsed1.errors.length,
        threatsDetected: res1.alerts.length,
        replacedPrevious: false,
        importCount: 1,
        validationErrors: [],
      },
      {
        id: 'upl-demo-2',
        filename: `${SAMPLE_DATASETS.firewall_portscan_json.filename} (Demo)`,
        datasetKey: key2,
        contentHash: hash2,
        format: 'json',
        uploadedAt: new Date(Date.now() - 3200_000).toISOString(),
        uploadedBy: 'system-seed',
        totalLines: parsed2.totalLines,
        validCount: parsed2.parsed.length,
        invalidCount: parsed2.errors.length,
        threatsDetected: res2.alerts.length,
        replacedPrevious: false,
        importCount: 1,
        validationErrors: [],
      },
    ];

    const auditLogs: AuditLogEntry[] = [
      {
        id: 'aud-seed-01',
        timestamp: new Date(Date.now() - 3600_000).toISOString(),
        actorUsername: 'system',
        actorRole: 'system',
        action: 'INITIALIZE_DEMO_DATA',
        entityType: 'system',
        entityId: 'sentinelforge',
        summary: `Seeded ${events.length} synthetic demonstration log events, ${alerts.length} alerts, and trained Isolation Forest + Logistic Regression models.`,
      },
      ...(alerts.length > 2
        ? [
            {
              id: 'aud-seed-02',
              timestamp: new Date(Date.now() - 1800_000).toISOString(),
              actorUsername: 'analyst',
              actorRole: 'analyst' as const,
              action: 'ACKNOWLEDGE_ALERT',
              entityType: 'alert' as const,
              entityId: alerts[alerts.length - 1].id,
              summary: `Acknowledged demonstration alert "${alerts[alerts.length - 1].title}"`,
              previousValue: 'open',
              newValue: 'acknowledged',
            },
          ]
        : []),
    ];

    return {
      version: 2,
      sensitivity,
      splitRatio,
      seed,
      events,
      alerts,
      sequences,
      forensicCases,
      auditLogs,
      intelRecords,
      uploads,
      demoUsers: createDefaultDemoUsers(),
      mlEvaluation: this.pipeline.evaluationReport,
    };
  }

  private save(): void {
    const tmpPath = `${this.filePath}.tmp`;
    fs.writeFileSync(tmpPath, JSON.stringify(this.state, null, 2), 'utf8');
    fs.renameSync(tmpPath, this.filePath);
  }

  getState(): PersistedStore {
    return this.state;
  }

  getPipeline(): TrainedMLPipeline {
    return this.pipeline;
  }

  recordAudit(entry: Omit<AuditLogEntry, 'id' | 'timestamp'>): AuditLogEntry {
    const full: AuditLogEntry = {
      id: `aud-${crypto.randomBytes(5).toString('hex')}`,
      timestamp: new Date().toISOString(),
      ...entry,
    };
    this.state.auditLogs.unshift(full);
    if (this.state.auditLogs.length > 500) {
      this.state.auditLogs = this.state.auditLogs.slice(0, 500);
    }
    this.save();
    return full;
  }

  ingestEvents(
    filename: string,
    content: string,
    explicitFormat: 'csv' | 'json' | 'txt' | undefined,
    actor: PublicUser | null,
    isDemoData = false
  ): {
    upload: DatasetUploadRecord;
    newEventsCount: number;
    newAlertsCount: number;
    replacedExisting: boolean;
    totalEventsInStore: number;
    totalAlertsInStore: number;
    alerts: ThreatAlert[];
  } {
    const parseResult = parseSecurityLogs(filename, content, explicitFormat);
    const actorName = actor?.username ?? 'demo-guest';
    const actorRole = actor?.role ?? 'guest_demo';
    const datasetKey = normalizeDatasetKey(filename);
    const contentHash = computeContentHash(content);

    if (parseResult.parsed.length === 0) {
      const failedUpload: DatasetUploadRecord = {
        id: `upl-${crypto.randomBytes(4).toString('hex')}`,
        filename,
        datasetKey,
        contentHash,
        format: parseResult.format,
        uploadedAt: new Date().toISOString(),
        uploadedBy: actorName,
        totalLines: parseResult.totalLines,
        validCount: 0,
        invalidCount: parseResult.errors.length,
        threatsDetected: 0,
        replacedPrevious: false,
        importCount: 1,
        validationErrors: parseResult.errors.slice(0, 25),
      };
      this.state.uploads = [failedUpload, ...this.state.uploads].slice(0, 100);
      this.save();
      return {
        upload: failedUpload,
        newEventsCount: 0,
        newAlertsCount: 0,
        replacedExisting: false,
        totalEventsInStore: this.state.events.length,
        totalAlertsInStore: this.state.alerts.length,
        alerts: [],
      };
    }

    const analysis = analyzeEventsWithEngine(
      parseResult.parsed,
      filename,
      isDemoData,
      this.pipeline,
      this.state.sensitivity,
      { datasetKey, contentHash }
    );

    const matchesIncomingDataset = (item: { datasetKey?: string; contentHash?: string; sourceFile?: string }) => {
      const itemKey = item.datasetKey ?? (item.sourceFile ? normalizeDatasetKey(item.sourceFile) : undefined);
      return itemKey === datasetKey || (item.contentHash !== undefined && item.contentHash === contentHash);
    };

    const matchedOldAlerts = this.state.alerts.filter((a) => matchesIncomingDataset(a));
    const matchedOldEvents = this.state.events.filter((e) => matchesIncomingDataset(e));
    const priorSuccessfulUploads = this.state.uploads.filter(
      (u) =>
        u.validCount > 0 &&
        ((u.datasetKey ?? normalizeDatasetKey(u.filename)) === datasetKey || u.contentHash === contentHash)
    );
    const replacedExisting =
      matchedOldAlerts.length > 0 || matchedOldEvents.length > 0 || priorSuccessfulUploads.length > 0;
    const prevMaxImport = priorSuccessfulUploads.reduce((max, u) => Math.max(max, u.importCount ?? 1), 0);

    // Preserve prior analyst triage & forensic links when re-importing the same dataset
    const triageSnapshot = new Map<
      string,
      {
        oldId: string;
        status: ThreatAlert['status'];
        analystFeedback: ThreatAlert['analystFeedback'];
        acknowledgedBy?: string;
        acknowledgedAt?: string;
        resolvedBy?: string;
        resolvedAt?: string;
        lastModifiedBy?: string;
        lastModifiedAt?: string;
      }
    >();
    for (const oldAlert of matchedOldAlerts) {
      const sig = `${oldAlert.sourceIp}::${oldAlert.category}::${oldAlert.timestamp}`;
      triageSnapshot.set(sig, {
        oldId: oldAlert.id,
        status: oldAlert.status,
        analystFeedback: oldAlert.analystFeedback,
        acknowledgedBy: oldAlert.acknowledgedBy,
        acknowledgedAt: oldAlert.acknowledgedAt,
        resolvedBy: oldAlert.resolvedBy,
        resolvedAt: oldAlert.resolvedAt,
        lastModifiedBy: oldAlert.lastModifiedBy,
        lastModifiedAt: oldAlert.lastModifiedAt,
      });
    }

    const alertIdRemap = new Map<string, string>();
    for (const nextAlert of analysis.alerts) {
      const sig = `${nextAlert.sourceIp}::${nextAlert.category}::${nextAlert.timestamp}`;
      const prev = triageSnapshot.get(sig);
      if (prev) {
        nextAlert.status = prev.status;
        nextAlert.analystFeedback = prev.analystFeedback;
        nextAlert.acknowledgedBy = prev.acknowledgedBy;
        nextAlert.acknowledgedAt = prev.acknowledgedAt;
        nextAlert.resolvedBy = prev.resolvedBy;
        nextAlert.resolvedAt = prev.resolvedAt;
        nextAlert.lastModifiedBy = prev.lastModifiedBy;
        nextAlert.lastModifiedAt = prev.lastModifiedAt;
        if (prev.oldId !== nextAlert.id) {
          alertIdRemap.set(prev.oldId, nextAlert.id);
        }
      }
    }

    if (alertIdRemap.size > 0) {
      for (const fcase of this.state.forensicCases) {
        const mapped = alertIdRemap.get(fcase.alertId);
        if (mapped) fcase.alertId = mapped;
      }
    }

    const preservedEvents = this.state.events.filter((e) => !matchesIncomingDataset(e));
    const preservedAlerts = this.state.alerts.filter((a) => !matchesIncomingDataset(a));

    this.state.events = [...analysis.events, ...preservedEvents].slice(0, 2000);
    this.state.alerts = [...analysis.alerts, ...preservedAlerts];
    this.state.sequences = correlateAttackSequences(this.state.alerts);

    // Enrich IP intel cache locally without external requests
    const knownIps = new Set(this.state.intelRecords.map((r) => r.ip));
    for (const ev of analysis.events) {
      if (!knownIps.has(ev.sourceIp)) {
        knownIps.add(ev.sourceIp);
        this.state.intelRecords.unshift(analyzeLocalIpIntel(ev.sourceIp));
      }
    }

    const upload: DatasetUploadRecord = {
      id: `upl-${crypto.randomBytes(4).toString('hex')}`,
      filename,
      datasetKey,
      contentHash,
      format: parseResult.format,
      uploadedAt: new Date().toISOString(),
      uploadedBy: actorName,
      totalLines: parseResult.totalLines,
      validCount: parseResult.parsed.length,
      invalidCount: parseResult.errors.length,
      threatsDetected: analysis.alerts.length,
      replacedPrevious: replacedExisting,
      importCount: prevMaxImport + 1,
      validationErrors: parseResult.errors.slice(0, 25),
    };
    this.state.uploads = [upload, ...this.state.uploads].slice(0, 100);

    this.recordAudit({
      actorUsername: actorName,
      actorRole,
      action: 'INGEST_AND_ANALYZE_LOGS',
      entityType: 'dataset',
      entityId: upload.id,
      summary: `${replacedExisting ? 'Re-analyzed & replaced prior import of' : 'Ingested'} "${filename}" (${parseResult.parsed.length} valid, ${parseResult.errors.length} invalid rows) -> ${analysis.alerts.length} threat(s) detected.`,
    });

    return {
      upload,
      newEventsCount: analysis.events.length,
      newAlertsCount: analysis.alerts.length,
      replacedExisting,
      totalEventsInStore: this.state.events.length,
      totalAlertsInStore: this.state.alerts.length,
      alerts: analysis.alerts,
    };
  }

  updateAlertStatus(
    alertId: string,
    status: 'open' | 'acknowledged' | 'resolved',
    actor: PublicUser | null
  ): ThreatAlert | null {
    const alert = this.state.alerts.find((a) => a.id === alertId);
    if (!alert) return null;

    const prevStatus = alert.status;
    const now = new Date().toISOString();
    const actorName = actor?.username ?? 'demo-guest';
    const actorRole = actor?.role ?? 'guest_demo';

    alert.status = status;
    alert.lastModifiedBy = actorName;
    alert.lastModifiedAt = now;
    if (status === 'acknowledged') {
      alert.acknowledgedBy = actorName;
      alert.acknowledgedAt = now;
    } else if (status === 'resolved') {
      alert.resolvedBy = actorName;
      alert.resolvedAt = now;
    }

    this.recordAudit({
      actorUsername: actorName,
      actorRole,
      action: status === 'acknowledged' ? 'ACKNOWLEDGE_ALERT' : status === 'resolved' ? 'RESOLVE_ALERT' : 'REOPEN_ALERT',
      entityType: 'alert',
      entityId: alert.id,
      summary: `Changed alert "${alert.title}" status from ${prevStatus} to ${status}.`,
      previousValue: prevStatus,
      newValue: status,
    });

    return alert;
  }

  submitAlertFeedback(
    alertId: string,
    feedback: 'true_positive' | 'false_positive',
    actor: PublicUser | null
  ): ThreatAlert | null {
    const alert = this.state.alerts.find((a) => a.id === alertId);
    if (!alert) return null;

    const prev = alert.analystFeedback;
    const actorName = actor?.username ?? 'demo-guest';
    const actorRole = actor?.role ?? 'guest_demo';
    alert.analystFeedback = feedback;
    alert.lastModifiedBy = actorName;
    alert.lastModifiedAt = new Date().toISOString();

    this.recordAudit({
      actorUsername: actorName,
      actorRole,
      action: 'SUBMIT_ML_FEEDBACK',
      entityType: 'alert',
      entityId: alert.id,
      summary: `Marked alert "${alert.title}" as ${feedback.replace('_', ' ')} for supervised retraining.`,
      previousValue: prev,
      newValue: feedback,
    });

    return alert;
  }

  createOrGetForensicCase(alertId: string, actor: PublicUser | null): ForensicCase | null {
    const existing = this.state.forensicCases.find((c) => c.alertId === alertId);
    if (existing) return existing;

    const alert = this.state.alerts.find((a) => a.id === alertId);
    if (!alert) return null;

    const actorName = actor?.username ?? 'demo-guest';
    const actorRole = actor?.role ?? 'guest_demo';
    const relatedEvents = this.state.events.filter((e) => alert.eventIds.includes(e.id));
    const rawArtifacts = relatedEvents.map((e) => e.rawLine).slice(0, 12);
    const digest = crypto
      .createHash('sha256')
      .update(JSON.stringify({ alertId: alert.id, rawArtifacts }))
      .digest('hex');

    const now = new Date().toISOString();
    const newCase: ForensicCase = {
      id: `fcase-${crypto.randomBytes(4).toString('hex')}`,
      alertId: alert.id,
      title: `Forensic Case: ${alert.title}`,
      severity: alert.severity,
      sourceIp: alert.sourceIp,
      status: 'investigating',
      evidenceSha256: digest,
      evidenceSummary: `Captured ${relatedEvents.length} correlated log record(s) from ${alert.sourceIp} (${alert.mitre.tacticId} ${alert.mitre.techniqueId}).`,
      rawArtifacts,
      timeline: [
        { timestamp: alert.timestamp, event: `Initial detection (${alert.category})`, actor: 'Detection Engine' },
        { timestamp: now, event: 'Forensic evidence container & SHA-256 digest created', actor: actorName },
      ],
      notes: [],
      createdAt: now,
      updatedAt: now,
      isDemoData: alert.isDemoData,
    };

    this.state.forensicCases.unshift(newCase);
    this.recordAudit({
      actorUsername: actorName,
      actorRole,
      action: 'OPEN_FORENSIC_CASE',
      entityType: 'forensic_case',
      entityId: newCase.id,
      summary: `Opened forensic investigation case for alert "${alert.title}" (SHA-256: ${digest.slice(0, 12)}...).`,
    });

    return newCase;
  }

  addForensicNote(
    caseId: string,
    content: string,
    status: 'investigating' | 'contained' | 'closed' | undefined,
    actor: PublicUser | null
  ): ForensicCase | null {
    const fcase = this.state.forensicCases.find((c) => c.id === caseId);
    if (!fcase) return null;

    const actorName = actor?.username ?? 'demo-guest';
    const actorRole = actor?.role ?? 'guest_demo';
    const now = new Date().toISOString();

    if (content.trim()) {
      fcase.notes.unshift({
        id: `fnote-${crypto.randomBytes(4).toString('hex')}`,
        author: actor?.displayName ?? 'Demo Guest Session',
        authorRole: actorRole,
        timestamp: now,
        content: content.trim(),
      });
      fcase.timeline.push({
        timestamp: now,
        event: `Investigation note added: "${content.trim().slice(0, 72)}"`,
        actor: actorName,
      });
    }

    const prevStatus = fcase.status;
    if (status && status !== prevStatus) {
      fcase.status = status;
      fcase.timeline.push({
        timestamp: now,
        event: `Case status changed from ${prevStatus} to ${status}`,
        actor: actorName,
      });
    }
    fcase.updatedAt = now;

    this.recordAudit({
      actorUsername: actorName,
      actorRole,
      action: 'UPDATE_FORENSIC_CASE',
      entityType: 'forensic_case',
      entityId: fcase.id,
      summary: `Updated forensic case "${fcase.title}"${status && status !== prevStatus ? ` (status: ${status})` : ' (added investigation note)'}.`,
      previousValue: prevStatus,
      newValue: fcase.status,
    });

    return fcase;
  }

  upsertIntelRecord(record: ThreatIntelRecord): void {
    const idx = this.state.intelRecords.findIndex((r) => r.ip === record.ip);
    if (idx >= 0) this.state.intelRecords[idx] = record;
    else this.state.intelRecords.unshift(record);
    this.save();
  }

  updateSensitivity(level: SensitivityLevel, actor: PublicUser): SensitivityConfig {
    const prev = this.state.sensitivity.level;
    this.state.sensitivity = getSensitivityPreset(level);
    this.recordAudit({
      actorUsername: actor.username,
      actorRole: actor.role,
      action: 'UPDATE_SENSITIVITY',
      entityType: 'settings',
      entityId: 'sensitivity',
      summary: `Administrator updated detection sensitivity from ${prev} to ${level}.`,
      previousValue: prev,
      newValue: level,
    });
    return this.state.sensitivity;
  }

  retrainPipeline(splitRatio: number, seed: number, includeFeedback: boolean, actor: PublicUser): MLEvaluationReport {
    this.state.splitRatio = splitRatio;
    this.state.seed = seed;
    const report = this.retrainPipelineInternal(splitRatio, seed, includeFeedback);
    this.recordAudit({
      actorUsername: actor.username,
      actorRole: actor.role,
      action: 'RETRAIN_ML_MODELS',
      entityType: 'ml_model',
      entityId: 'ensemble-v1',
      summary: `Retrained Isolation Forest + Logistic Regression (split=${Math.round(splitRatio * 100)}/${Math.round((1 - splitRatio) * 100)}, seed=${seed}, feedback=${report.feedbackSamplesIncluded}). Test F1=${(report.hybridEnsemble.f1Score * 100).toFixed(1)}%.`,
    });
    return report;
  }

  private retrainPipelineInternal(splitRatio: number, seed: number, includeFeedback: boolean): MLEvaluationReport {
    const baseDataset = buildReproducibleLabeledDataset(seed);
    const trainingRecords = baseDataset.map((d) => ({ vector: d.vector, label: d.label }));

    let feedbackCount = 0;
    if (includeFeedback) {
      const eventMap = new Map(this.state.events.map((e) => [e.id, e]));
      for (const alert of this.state.alerts) {
        if (alert.analystFeedback === 'true_positive' || alert.analystFeedback === 'false_positive') {
          const ev = eventMap.get(alert.primaryEventId);
          if (ev) {
            const label: 0 | 1 = alert.analystFeedback === 'true_positive' ? 1 : 0;
            trainingRecords.push({
              vector: featuresToVector(ev.features),
              label,
            });
            feedbackCount++;
          }
        }
      }
    }

    this.pipeline = trainAndEvaluatePipeline(trainingRecords, splitRatio, seed, feedbackCount);
    this.state.mlEvaluation = this.pipeline.evaluationReport;
    if (this.state) {
      this.save();
    }
    return this.pipeline.evaluationReport;
  }

  resetToDemo(actor: PublicUser): PersistedStore {
    this.state = this.createInitialSeedState();
    this.recordAudit({
      actorUsername: actor.username,
      actorRole: actor.role,
      action: 'RESET_DEMO_DATA',
      entityType: 'system',
      entityId: 'sentinelforge',
      summary: 'Administrator reset platform state to baseline synthetic demonstration dataset.',
    });
    return this.state;
  }

  registerDemoAnalyst(username: string, password: string, displayName: string): { user?: PublicUser; error?: string } {
    const cleanUser = username.trim().toLowerCase().replace(/[^a-z0-9._-]/g, '');
    if (cleanUser.length < 3 || password.length < 6) {
      return { error: 'Username must be at least 3 characters and password at least 6 characters.' };
    }
    if (this.state.demoUsers.some((u) => u.username === cleanUser)) {
      return { error: `Demo user "${cleanUser}" already exists.` };
    }
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(password, salt, 32).toString('hex');
    const created: StoredDemoUser = {
      id: `usr-${crypto.randomBytes(4).toString('hex')}`,
      username: cleanUser,
      displayName: displayName.trim() || cleanUser,
      role: 'analyst',
      salt,
      passwordHash: hash,
      isDemoAccount: true,
    };
    this.state.demoUsers.push(created);
    this.recordAudit({
      actorUsername: created.username,
      actorRole: 'analyst',
      action: 'REGISTER_DEMO_ANALYST',
      entityType: 'auth',
      entityId: created.id,
      summary: `Registered new local demonstration Analyst account "${created.username}".`,
    });
    return {
      user: {
        id: created.id,
        username: created.username,
        displayName: created.displayName,
        role: created.role,
        isDemoAccount: true,
      },
    };
  }
}

export function computeFeaturePreview(rawLineOrEvents: { events: SecurityEvent[] }): number[][] {
  return rawLineOrEvents.events.map((e) => featuresToVector(e.features));
}

export { extractEventFeatures };
