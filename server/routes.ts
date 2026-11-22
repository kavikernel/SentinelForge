import express, { type Response } from 'express';
import type { DashboardSummary, SensitivityLevel, Severity } from '../src/shared/types.ts';
import {
  attachAuthContext,
  requireRole,
  signSessionToken,
  toPublicUser,
  verifyPassword,
  type AuthenticatedRequest,
} from './auth.ts';
import { buildReproducibleLabeledDataset, SAMPLE_DATASETS } from './datasets.ts';
import { isPrivateOrReservedIp } from './features.ts';
import { analyzeLocalIpIntel, lookupOptInPublicFeed } from './intel.ts';
import type { SentinelStore } from './store.ts';

const API_DOCUMENTATION = [
  { method: 'GET', path: '/api/health', role: 'Public', description: 'Returns service health and active model metadata.' },
  { method: 'GET', path: '/api/dashboard', role: 'Public / Analyst', description: 'Aggregated SOC KPIs, severity counts, hourly trends, top suspicious IPs, and recent activity.' },
  { method: 'GET', path: '/api/logs', role: 'Public / Analyst', description: 'Paginated/searchable normalized security events and upload validation history.' },
  { method: 'POST', path: '/api/logs/upload', role: 'Analyst / Demo Session', description: 'Validates, parses (CSV/JSON/TXT), extracts features, and runs hybrid ML + rule detection.' },
  { method: 'POST', path: '/api/logs/sample/:sampleKey', role: 'Analyst / Demo Session', description: 'Loads and analyzes one of the bundled reproducible sample security log files.' },
  { method: 'GET', path: '/api/alerts', role: 'Public / Analyst', description: 'Lists detected threats with MITRE ATT&CK mappings, XAI attributions, and playbooks.' },
  { method: 'PATCH', path: '/api/alerts/:id/status', role: 'Analyst / Demo Session', description: 'Acknowledges, resolves, or reopens an alert and appends an immutable audit log entry.' },
  { method: 'POST', path: '/api/alerts/:id/feedback', role: 'Analyst / Demo Session', description: 'Records True Positive / False Positive analyst feedback for supervised retraining.' },
  { method: 'GET', path: '/api/correlations', role: 'Public / Analyst', description: 'Returns multi-stage attack sequences correlated by source IP and timeline.' },
  { method: 'GET', path: '/api/forensics', role: 'Public / Analyst', description: 'Lists digital forensic cases with SHA-256 evidence digests and timelines.' },
  { method: 'POST', path: '/api/forensics/from-alert/:alertId', role: 'Analyst / Demo Session', description: 'Opens or retrieves a forensic case for a given alert.' },
  { method: 'POST', path: '/api/forensics/:caseId/notes', role: 'Analyst / Demo Session', description: 'Adds an investigation note or updates case containment status (audited).' },
  { method: 'GET', path: '/api/intel', role: 'Public / Analyst', description: 'Lists IP classification and demo/verified intelligence records.' },
  { method: 'POST', path: '/api/intel/lookup', role: 'Analyst / Demo Session', description: 'Performs local IP analysis with optional opt-in public RDAP lookup (blocks private IPs).' },
  { method: 'GET', path: '/api/ml/evaluation', role: 'Public / Analyst', description: 'Returns Isolation Forest, Logistic Regression, and Hybrid Ensemble held-out test metrics.' },
  { method: 'POST', path: '/api/ml/retrain', role: 'Administrator Only', description: 'Retrains Isolation Forest and Logistic Regression with custom train/test split and feedback.' },
  { method: 'GET', path: '/api/audit', role: 'Public / Analyst', description: 'Returns immutable chronological audit trail of incident and admin actions.' },
  { method: 'GET', path: '/api/reports/export', role: 'Public / Analyst', description: 'Exports structured incident report data as CSV or JSON.' },
  { method: 'PATCH', path: '/api/settings/sensitivity', role: 'Administrator Only', description: 'Updates detection sensitivity thresholds (Low, Balanced, High).' },
  { method: 'POST', path: '/api/system/reset', role: 'Administrator Only', description: 'Resets platform store back to baseline synthetic demonstration dataset.' },
  { method: 'POST', path: '/api/auth/login', role: 'Public', description: 'Authenticates a local demo Analyst or Administrator account (scrypt + HMAC Bearer).' },
  { method: 'POST', path: '/api/auth/register', role: 'Public', description: 'Registers a new local demo Analyst account.' },
];

function csvEscape(val: unknown): string {
  const s = String(val ?? '');
  if (s.includes(',') || s.includes('"') || s.includes('\n')) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

export function createApiRouter(store: SentinelStore): express.Router {
  const router = express.Router();
  router.use(attachAuthContext);

  router.get('/health', (_req, res: Response) => {
    const state = store.getState();
    res.json({
      status: 'ok',
      service: 'SENTINELFORGE',
      eventsCount: state.events.length,
      alertsCount: state.alerts.length,
      models: ['IsolationForest', 'LogisticRegression'],
    });
  });

  // Authentication Endpoints (Local Demo Auth)
  router.get('/auth/me', (req: AuthenticatedRequest, res: Response) => {
    res.json({
      authenticated: Boolean(req.authUser),
      user: req.authUser ?? null,
      demoNotice: 'Local demonstration authentication only (scrypt + HMAC Bearer token).',
    });
  });

  router.post('/auth/login', (req: AuthenticatedRequest, res: Response) => {
    const username = typeof req.body?.username === 'string' ? req.body.username.trim().toLowerCase() : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    if (!username || !password) {
      res.status(400).json({ error: 'Username and password are required.' });
      return;
    }

    const userRecord = store.getState().demoUsers.find((u) => u.username === username);
    if (!userRecord || !verifyPassword(password, userRecord.salt, userRecord.passwordHash)) {
      res.status(401).json({ error: 'Invalid demo username or password.' });
      return;
    }

    const pub = toPublicUser(userRecord);
    const token = signSessionToken(pub);
    store.recordAudit({
      actorUsername: pub.username,
      actorRole: pub.role,
      action: 'DEMO_LOGIN',
      entityType: 'auth',
      entityId: pub.id,
      summary: `Signed in as ${pub.displayName} (${pub.role}).`,
    });

    res.json({ token, user: pub });
  });

  router.post('/auth/register', (req: AuthenticatedRequest, res: Response) => {
    const username = typeof req.body?.username === 'string' ? req.body.username : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    const displayName = typeof req.body?.displayName === 'string' ? req.body.displayName : '';

    const result = store.registerDemoAnalyst(username, password, displayName);
    if (result.error || !result.user) {
      res.status(400).json({ error: result.error ?? 'Registration failed.' });
      return;
    }
    const token = signSessionToken(result.user);
    res.status(201).json({ token, user: result.user });
  });

  // Dashboard Summary
  router.get('/dashboard', (_req, res: Response) => {
    const state = store.getState();
    const severityCounts: Record<Severity, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    const categoryMap = new Map<string, number>();
    const ipStats = new Map<
      string,
      { alertCount: number; maxSeverity: Severity; totalScore: number }
    >();

    const sevRank = (s: Severity) => (s === 'Critical' ? 4 : s === 'High' ? 3 : s === 'Medium' ? 2 : 1);

    let openAlerts = 0;
    let acknowledgedAlerts = 0;
    let resolvedAlerts = 0;

    for (const al of state.alerts) {
      severityCounts[al.severity]++;
      categoryMap.set(al.category, (categoryMap.get(al.category) ?? 0) + 1);
      if (al.status === 'open') openAlerts++;
      else if (al.status === 'acknowledged') acknowledgedAlerts++;
      else resolvedAlerts++;

      const cur = ipStats.get(al.sourceIp) ?? { alertCount: 0, maxSeverity: 'Low' as Severity, totalScore: 0 };
      cur.alertCount++;
      cur.totalScore += al.confidence;
      if (sevRank(al.severity) > sevRank(cur.maxSeverity)) cur.maxSeverity = al.severity;
      ipStats.set(al.sourceIp, cur);
    }

    // Build chronological buckets by hour/day slice from actual events + alerts
    const bucketMap = new Map<string, { events: number; threats: number }>();
    for (const ev of state.events) {
      const bucket = ev.timestamp.slice(0, 13) + ':00';
      const cur = bucketMap.get(bucket) ?? { events: 0, threats: 0 };
      cur.events++;
      bucketMap.set(bucket, cur);
    }
    for (const al of state.alerts) {
      const bucket = al.timestamp.slice(0, 13) + ':00';
      const cur = bucketMap.get(bucket) ?? { events: 0, threats: 0 };
      cur.threats++;
      bucketMap.set(bucket, cur);
    }

    const trendSeries = Array.from(bucketMap.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .slice(-14)
      .map(([bucket, counts]) => ({
        bucket: bucket.slice(5, 16).replace('T', ' '),
        events: counts.events,
        threats: counts.threats,
      }));

    const topSuspiciousIps = Array.from(ipStats.entries())
      .map(([ip, st]) => ({
        ip,
        alertCount: st.alertCount,
        maxSeverity: st.maxSeverity,
        avgScore: Number((st.totalScore / st.alertCount).toFixed(1)),
        isPublic: !isPrivateOrReservedIp(ip),
      }))
      .sort((a, b) => b.avgScore - a.avgScore || b.alertCount - a.alertCount)
      .slice(0, 6);

    const summary: DashboardSummary = {
      totalEvents: state.events.length,
      totalThreats: state.alerts.length,
      openAlerts,
      acknowledgedAlerts,
      resolvedAlerts,
      severityCounts,
      categoryDistribution: Array.from(categoryMap.entries())
        .map(([category, count]) => ({ category, count }))
        .sort((a, b) => b.count - a.count),
      trendSeries,
      topSuspiciousIps,
      recentAlerts: state.alerts.slice(0, 6),
      recentActivity: state.auditLogs.slice(0, 8),
      correlatedSequencesCount: state.sequences.length,
    };

    res.json(summary);
  });

  // Log Analyzer & Dataset Management
  router.get('/logs', (req: AuthenticatedRequest, res: Response) => {
    const q = typeof req.query.q === 'string' ? req.query.q.trim().toLowerCase() : '';
    const action = typeof req.query.action === 'string' ? req.query.action.trim().toUpperCase() : '';
    const state = store.getState();

    const filtered = state.events.filter((ev) => {
      if (action && action !== 'ALL' && ev.action.toUpperCase() !== action) return false;
      if (!q) return true;
      return (
        ev.sourceIp.toLowerCase().includes(q) ||
        ev.destinationIp.toLowerCase().includes(q) ||
        ev.username.toLowerCase().includes(q) ||
        ev.message.toLowerCase().includes(q) ||
        ev.eventType.toLowerCase().includes(q) ||
        ev.sourceFile.toLowerCase().includes(q)
      );
    });

    res.json({
      events: filtered.slice(0, 250),
      totalCount: filtered.length,
      uploads: state.uploads,
      samples: Object.entries(SAMPLE_DATASETS).map(([key, val]) => ({
        key,
        name: val.name,
        filename: val.filename,
        format: val.format,
        description: val.description,
      })),
    });
  });

  router.post('/logs/upload', (req: AuthenticatedRequest, res: Response) => {
    const filename = typeof req.body?.filename === 'string' ? req.body.filename.trim() : '';
    const content = typeof req.body?.content === 'string' ? req.body.content : '';
    const formatRaw = req.body?.format;
    const format = formatRaw === 'csv' || formatRaw === 'json' || formatRaw === 'txt' ? formatRaw : undefined;

    if (!filename || !content) {
      res.status(400).json({ error: 'Both filename and log content are required.' });
      return;
    }
    if (content.length > 2_000_000) {
      res.status(413).json({ error: 'Log payload exceeds the 2 MB local analysis limit.' });
      return;
    }

    const result = store.ingestEvents(filename, content, format, req.authUser ?? null, false);
    if (result.newEventsCount === 0) {
      res.status(422).json({
        error: result.upload.validationErrors[0]?.reason ?? 'No valid log entries found in file.',
        upload: result.upload,
      });
      return;
    }

    res.status(201).json(result);
  });

  router.post('/logs/sample/:sampleKey', (req: AuthenticatedRequest, res: Response) => {
    const key = req.params.sampleKey as keyof typeof SAMPLE_DATASETS;
    const sample = SAMPLE_DATASETS[key];
    if (!sample) {
      res.status(404).json({ error: 'Unknown sample dataset key.' });
      return;
    }
    const result = store.ingestEvents(
      `${sample.filename} (Demo)`,
      sample.content,
      sample.format,
      req.authUser ?? null,
      true
    );
    res.status(201).json(result);
  });

  // Alerts & Feedback
  router.get('/alerts', (req: AuthenticatedRequest, res: Response) => {
    const q = typeof req.query.q === 'string' ? req.query.q.trim().toLowerCase() : '';
    const severity = typeof req.query.severity === 'string' ? req.query.severity : 'ALL';
    const status = typeof req.query.status === 'string' ? req.query.status : 'ALL';
    const category = typeof req.query.category === 'string' ? req.query.category : 'ALL';

    const filtered = store.getState().alerts.filter((al) => {
      if (severity !== 'ALL' && al.severity !== severity) return false;
      if (status !== 'ALL' && al.status !== status) return false;
      if (category !== 'ALL' && al.category !== category) return false;
      if (!q) return true;
      return (
        al.title.toLowerCase().includes(q) ||
        al.sourceIp.toLowerCase().includes(q) ||
        al.username.toLowerCase().includes(q) ||
        al.mitre.techniqueId.toLowerCase().includes(q) ||
        al.mitre.tacticName.toLowerCase().includes(q) ||
        al.description.toLowerCase().includes(q)
      );
    });

    res.json({ alerts: filtered, total: filtered.length });
  });

  router.patch('/alerts/:id/status', (req: AuthenticatedRequest, res: Response) => {
    const status = req.body?.status;
    if (status !== 'open' && status !== 'acknowledged' && status !== 'resolved') {
      res.status(400).json({ error: 'Status must be open, acknowledged, or resolved.' });
      return;
    }
    const updated = store.updateAlertStatus(req.params.id, status, req.authUser ?? null);
    if (!updated) {
      res.status(404).json({ error: 'Alert not found.' });
      return;
    }
    res.json({ alert: updated });
  });

  router.post('/alerts/:id/feedback', (req: AuthenticatedRequest, res: Response) => {
    const feedback = req.body?.feedback;
    if (feedback !== 'true_positive' && feedback !== 'false_positive') {
      res.status(400).json({ error: 'Feedback must be true_positive or false_positive.' });
      return;
    }
    const updated = store.submitAlertFeedback(req.params.id, feedback, req.authUser ?? null);
    if (!updated) {
      res.status(404).json({ error: 'Alert not found.' });
      return;
    }
    res.json({ alert: updated });
  });

  // Attack Correlation
  router.get('/correlations', (_req, res: Response) => {
    res.json({ sequences: store.getState().sequences });
  });

  // Digital Forensics
  router.get('/forensics', (_req, res: Response) => {
    res.json({ cases: store.getState().forensicCases });
  });

  router.post('/forensics/from-alert/:alertId', (req: AuthenticatedRequest, res: Response) => {
    const fcase = store.createOrGetForensicCase(req.params.alertId, req.authUser ?? null);
    if (!fcase) {
      res.status(404).json({ error: 'Referenced alert not found.' });
      return;
    }
    res.status(201).json({ forensicCase: fcase });
  });

  router.post('/forensics/:caseId/notes', (req: AuthenticatedRequest, res: Response) => {
    const content = typeof req.body?.content === 'string' ? req.body.content : '';
    const statusRaw = req.body?.status;
    const status =
      statusRaw === 'investigating' || statusRaw === 'contained' || statusRaw === 'closed'
        ? statusRaw
        : undefined;

    if (!content.trim() && !status) {
      res.status(400).json({ error: 'Note content or updated case status is required.' });
      return;
    }

    const updated = store.addForensicNote(req.params.caseId, content, status, req.authUser ?? null);
    if (!updated) {
      res.status(404).json({ error: 'Forensic case not found.' });
      return;
    }
    res.json({ forensicCase: updated });
  });

  // Threat Intelligence
  router.get('/intel', (_req, res: Response) => {
    res.json({ records: store.getState().intelRecords });
  });

  router.post('/intel/lookup', async (req: AuthenticatedRequest, res: Response) => {
    const ip = typeof req.body?.ip === 'string' ? req.body.ip.trim() : '';
    const includePublicFeed = Boolean(req.body?.includePublicFeed);

    if (!ip) {
      res.status(400).json({ error: 'IP address is required.' });
      return;
    }

    if (!includePublicFeed) {
      const record = analyzeLocalIpIntel(ip);
      if (record.ipVersion !== 'Invalid') store.upsertIntelRecord(record);
      res.json({
        record,
        lookupStatus: record.ipVersion === 'Invalid' ? 'invalid_ip' : 'local_only',
        statusDetail: 'Analyzed locally using IP scope classifier and offline demonstration threat feed.',
      });
      return;
    }

    const result = await lookupOptInPublicFeed(ip);
    if (result.record.ipVersion !== 'Invalid') {
      store.upsertIntelRecord(result.record);
    }
    res.json(result);
  });

  // Machine Learning Evaluation & Dataset Info
  router.get('/ml/evaluation', (_req, res: Response) => {
    const state = store.getState();
    const datasetPreview = buildReproducibleLabeledDataset(state.seed)
      .slice(0, 12)
      .map((d) => ({
        id: d.id,
        timestamp: d.event.timestamp,
        sourceIp: d.event.sourceIp,
        port: d.event.destinationPort,
        category: d.category,
        label: d.label,
      }));
    res.json({
      evaluation: state.mlEvaluation,
      datasetPreview,
    });
  });

  router.post('/ml/retrain', requireRole(['administrator']), (req: AuthenticatedRequest, res: Response) => {
    const splitRaw = Number(req.body?.splitRatio ?? 0.75);
    const seedRaw = Number(req.body?.seed ?? 2026);
    const includeFeedback = Boolean(req.body?.includeFeedback);

    if (!Number.isFinite(splitRaw) || splitRaw < 0.5 || splitRaw > 0.9) {
      res.status(400).json({ error: 'Train split ratio must be between 0.50 and 0.90.' });
      return;
    }
    const seed = Number.isFinite(seedRaw) ? Math.abs(Math.round(seedRaw)) : 2026;
    const evaluation = store.retrainPipeline(splitRaw, seed, includeFeedback, req.authUser!);
    res.json({ evaluation });
  });

  // Audit Trail
  router.get('/audit', (req: AuthenticatedRequest, res: Response) => {
    const action = typeof req.query.action === 'string' ? req.query.action.trim() : '';
    const logs = store.getState().auditLogs.filter((l) => (!action || action === 'ALL' ? true : l.action === action));
    res.json({ auditLogs: logs });
  });

  // Incident Reports Export
  router.get('/reports/export', (req: AuthenticatedRequest, res: Response) => {
    const format = req.query.format === 'json' ? 'json' : 'csv';
    const severity = typeof req.query.severity === 'string' ? req.query.severity : 'ALL';
    const category = typeof req.query.category === 'string' ? req.query.category : 'ALL';
    const status = typeof req.query.status === 'string' ? req.query.status : 'ALL';
    const scope = typeof req.query.scope === 'string' ? req.query.scope : 'incidents';
    const state = store.getState();

    const filteredAlerts = state.alerts.filter((al) => {
      if (severity !== 'ALL' && al.severity !== severity) return false;
      if (category !== 'ALL' && al.category !== category) return false;
      if (status !== 'ALL' && al.status !== status) return false;
      return true;
    });

    if (format === 'json') {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="sentinelforge-${scope}-report.json"`);
      res.send(
        JSON.stringify(
          {
            generatedAt: new Date().toISOString(),
            platform: 'SENTINELFORGE',
            scope,
            filters: { severity, category, status },
            totalEvents: state.events.length,
            exportedAlertsCount: filteredAlerts.length,
            alerts: filteredAlerts,
            correlatedSequences: state.sequences,
            forensicCases: scope === 'forensics' ? state.forensicCases : undefined,
          },
          null,
          2
        )
      );
      return;
    }

    const headers = [
      'Alert ID',
      'Timestamp',
      'Severity',
      'Category',
      'Status',
      'Source IP',
      'Destination IP',
      'Username',
      'MITRE Tactic',
      'MITRE Technique',
      'Confidence (%)',
      'ML Probability',
      'Isolation Forest Score',
      'XAI Top Reason',
      'Analyst Feedback',
      'Recommended Action',
    ];
    const rows = filteredAlerts.map((al) => [
      al.id,
      al.timestamp,
      al.severity,
      al.category,
      al.status,
      al.sourceIp,
      al.destinationIp,
      al.username,
      `${al.mitre.tacticId} ${al.mitre.tacticName}`,
      `${al.mitre.techniqueId} ${al.mitre.techniqueName}`,
      al.confidence,
      al.mlProbability,
      al.anomalyScore,
      al.xai.reasons[0] ?? 'Rule & ML ensemble detection',
      al.analystFeedback,
      al.recommendations[0] ?? 'Investigate alert evidence',
    ]);

    const csv = [headers.map(csvEscape).join(','), ...rows.map((r) => r.map(csvEscape).join(','))].join('\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="sentinelforge-${scope}-report.csv"`);
    res.send(csv);
  });

  // Settings & System Reset (Admin RBAC enforced)
  router.get('/settings', (_req, res: Response) => {
    const state = store.getState();
    res.json({
      sensitivity: state.sensitivity,
      splitRatio: state.splitRatio,
      seed: state.seed,
      eventsCount: state.events.length,
      alertsCount: state.alerts.length,
    });
  });

  router.patch('/settings/sensitivity', requireRole(['administrator']), (req: AuthenticatedRequest, res: Response) => {
    const level = req.body?.level as SensitivityLevel;
    if (level !== 'low' && level !== 'balanced' && level !== 'high') {
      res.status(400).json({ error: 'Sensitivity level must be low, balanced, or high.' });
      return;
    }
    const updated = store.updateSensitivity(level, req.authUser!);
    res.json({ sensitivity: updated });
  });

  router.post('/system/reset', requireRole(['administrator']), (req: AuthenticatedRequest, res: Response) => {
    const nextState = store.resetToDemo(req.authUser!);
    res.json({
      message: 'Platform reset to synthetic demonstration baseline.',
      eventsCount: nextState.events.length,
      alertsCount: nextState.alerts.length,
    });
  });

  // REST API Docs Metadata
  router.get('/docs', (_req, res: Response) => {
    res.json({
      version: '1.0.0',
      baseUrl: '/api',
      authScheme: 'Authorization: Bearer <token> (Optional for read/demo triage; Administrator role required for sensitivity, ML retraining, and reset)',
      endpoints: API_DOCUMENTATION,
    });
  });

  return router;
}
