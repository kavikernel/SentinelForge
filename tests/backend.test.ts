import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';
import { createServer } from '../server.ts';
import { buildReproducibleLabeledDataset } from '../server/datasets.ts';
import { fitScaler, transformWithScaler } from '../server/features.ts';
import { analyzeLocalIpIntel, classifyIpScope, lookupOptInPublicFeed } from '../server/intel.ts';
import { IsolationForest, trainAndEvaluatePipeline } from '../server/mlEngine.ts';
import { parseSecurityLogs } from '../server/parsers.ts';

describe('SentinelForge Log Parsers', () => {
  test('parses valid CSV logs and rejects malformed rows gracefully', () => {
    const csv = [
      'timestamp,source_ip,destination_ip,destination_port,protocol,username,event_type,action,status_code,message',
      '2026-11-21T02:11:02Z,185.220.101.45,10.0.1.12,22,TCP,root,AUTH_FAILURE,FAILED,401,Failed password',
      'bad-timestamp,999.999.1.1,10.0.1.12,22,TCP,root,AUTH_FAILURE,FAILED,401,Bad IP row',
    ].join('\n');

    const res = parseSecurityLogs('test.csv', csv, 'csv');
    assert.equal(res.parsed.length, 1);
    assert.equal(res.errors.length, 1);
    assert.equal(res.parsed[0].sourceIp, '185.220.101.45');
  });

  test('parses JSON array and rejects invalid JSON cleanly', () => {
    const valid = parseSecurityLogs(
      'events.json',
      JSON.stringify([{ timestamp: '2026-11-21T10:00:00Z', sourceIp: '198.51.100.77', destinationPort: 443, message: 'Probe' }]),
      'json'
    );
    assert.equal(valid.parsed.length, 1);

    const invalid = parseSecurityLogs('broken.json', '{ not json', 'json');
    assert.equal(invalid.parsed.length, 0);
    assert.ok(invalid.errors.length > 0);
  });

  test('parses raw TXT syslog lines extracting IPs, usernames, and ports and rejects malformed lines', () => {
    const txt = [
      '2026-11-21T01:22:10Z srv-auth sshd[123]: Failed password for invalid user oracle from 91.240.118.14 port 22 ssh2',
      'corrupted line missing timestamp 91.240.118.14',
      '2026-11-21T01:22:15Z no_ip_here invalid incomplete message',
      '2026-11-21T01:22:20Z srv-auth sshd[123]: Failed password from 91.240.118.14 port 99999',
    ].join('\n');
    const res = parseSecurityLogs('auth.txt', txt, 'txt');
    assert.equal(res.parsed.length, 1);
    assert.equal(res.errors.length, 3);
    assert.equal(res.parsed[0].sourceIp, '91.240.118.14');
    assert.equal(res.parsed[0].username, 'oracle');
    assert.equal(res.parsed[0].destinationPort, 22);
  });

  test('rejects incomplete CSV rows and invalid JSON records cleanly', () => {
    const csv = [
      'timestamp,source_ip,destination_ip,destination_port,protocol,username,event_type,action,status_code,message',
      '2026-11-21T02:11:02Z,185.220.101.45,10.0.1.12,22,TCP,root,AUTH_FAILURE,FAILED,401,Failed password',
      '2026-11-21T02:11:03Z,185.220.101.45,10.0.1.12',
      '2026-11-21T02:11:04Z,185.220.101.45,10.0.1.12,notaport,TCP,root,AUTH_FAILURE,FAILED,401,Bad port',
      '2026-11-21T02:11:05Z,185.220.101.45,10.0.1.12,22,TCP,root,AUTH_FAILURE,FAILED,401,',
    ].join('\n');
    const csvRes = parseSecurityLogs('partial.csv', csv, 'csv');
    assert.equal(csvRes.parsed.length, 1);
    assert.equal(csvRes.errors.length, 3);

    const jsonRes = parseSecurityLogs(
      'partial.json',
      JSON.stringify([
        { timestamp: '2026-11-21T10:00:00Z', sourceIp: '198.51.100.77', destinationPort: 443, message: 'Valid probe' },
        { timestamp: '2026-11-21T10:00:01Z', sourceIp: '198.51.100.77', destinationPort: 70000, message: 'Bad port' },
        { timestamp: '2026-11-21T10:00:02Z', sourceIp: '198.51.100.77', message: '' },
        'not-an-object',
      ]),
      'json'
    );
    assert.equal(jsonRes.parsed.length, 1);
    assert.equal(jsonRes.errors.length, 3);
  });
});

describe('SentinelForge ML Pipeline & Leakage Prevention', () => {
  test('scaler fits strictly on training split without test contamination', () => {
    const train = [[10, 0], [12, 0], [14, 0]];
    const testSplit = [[1000, 10]];
    const scaler = fitScaler(train);
    assert.equal(scaler.means[0], 12);
    const scaledTest = transformWithScaler(testSplit, scaler);
    assert.ok(scaledTest[0][0] > 100);
  });

  test('Isolation Forest assigns higher anomaly score to clear outliers', () => {
    const normal = Array.from({ length: 40 }, (_, i) => [0.1 * (i % 3), -0.1 * (i % 2), 0]);
    const forest = new IsolationForest();
    forest.fit(normal, 48, 32, 42);

    const inlier = forest.scorePoint([0.1, -0.05, 0]);
    const outlier = forest.scorePoint([12.5, 9.8, 7.2]);
    assert.ok(outlier.anomalyScore > inlier.anomalyScore);
  });

  test('Reproducible labeled dataset evaluation produces valid non-fabricated metrics', () => {
    const ds = buildReproducibleLabeledDataset(2026);
    assert.equal(ds.length, 240);

    const report = trainAndEvaluatePipeline(
      ds.map((d) => ({ vector: d.vector, label: d.label })),
      0.75,
      2026,
      0
    ).evaluationReport;

    assert.equal(report.trainCount + report.testCount, 240);
    const cm = report.hybridEnsemble.confusionMatrix;
    assert.equal(cm.tp + cm.fp + cm.tn + cm.fn, report.testCount);
    assert.ok(report.hybridEnsemble.f1Score >= 0.7 && report.hybridEnsemble.f1Score <= 1);
    assert.ok(report.isolationForest.precision >= 0 && report.isolationForest.precision <= 1);
    assert.ok(report.logisticRegression.recall >= 0 && report.logisticRegression.recall <= 1);
  });
});

describe('SentinelForge Threat Intelligence & SSRF Guard', () => {
  test('distinguishes RFC 1918 private IPs from public routable IPs', () => {
    assert.equal(classifyIpScope('192.168.1.10').scope, 'Private / Reserved');
    assert.equal(classifyIpScope('169.254.169.254').scope, 'Private / Reserved');
    assert.equal(classifyIpScope('8.8.8.8').scope, 'Public Routable');
    assert.equal(analyzeLocalIpIntel('185.220.101.45').provenance, 'Demo Intelligence');
  });

  test('blocks outbound public RDAP lookup for private/metadata IPs', async () => {
    const res = await lookupOptInPublicFeed('169.254.169.254');
    assert.equal(res.lookupStatus, 'blocked_private');
  });
});

describe('SentinelForge REST API, RBAC, and Audit Logging', () => {
  let tmpDir: string;
  let baseUrl: string;
  let serverHandle: ReturnType<import('express').Express['listen']>;

  before(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinelforge-test-'));
    const { app } = await createServer({ dataDir: tmpDir, skipVite: true });
    await new Promise<void>((resolve) => {
      serverHandle = app.listen(0, '127.0.0.1', () => {
        const addr = serverHandle.address();
        if (addr && typeof addr === 'object') {
          baseUrl = `http://127.0.0.1:${addr.port}`;
        }
        resolve();
      });
    });
  });

  after(async () => {
    await new Promise<void>((resolve) => serverHandle.close(() => resolve()));
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('enforces Analyst vs Administrator RBAC and records incident audit trail', async () => {
    // 1. Unauthenticated request to Admin endpoint is 401
    const unauthRes = await fetch(`${baseUrl}/api/settings/sensitivity`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ level: 'high' }),
    });
    assert.equal(unauthRes.status, 401);

    // 2. Sign in as Demo Analyst
    const analystLogin = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'analyst', password: 'analyst-demo-2026' }),
    });
    assert.equal(analystLogin.status, 200);
    const { token: analystToken } = (await analystLogin.json()) as { token: string };

    // 3. Analyst is denied Admin-only sensitivity endpoint (403)
    const forbiddenRes = await fetch(`${baseUrl}/api/settings/sensitivity`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${analystToken}`,
      },
      body: JSON.stringify({ level: 'high' }),
    });
    assert.equal(forbiddenRes.status, 403);

    // 4. Analyst CAN acknowledge an alert, and it creates an audit log entry
    const alertsRes = await fetch(`${baseUrl}/api/alerts`);
    const { alerts } = (await alertsRes.json()) as { alerts: Array<{ id: string }> };
    assert.ok(alerts.length > 0);
    const targetId = alerts[0].id;

    const ackRes = await fetch(`${baseUrl}/api/alerts/${targetId}/status`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${analystToken}`,
      },
      body: JSON.stringify({ status: 'resolved' }),
    });
    assert.equal(ackRes.status, 200);

    const auditRes = await fetch(`${baseUrl}/api/audit`);
    const { auditLogs } = (await auditRes.json()) as {
      auditLogs: Array<{ actorUsername: string; action: string; entityId: string }>;
    };
    assert.ok(
      auditLogs.some((l) => l.actorUsername === 'analyst' && l.action === 'RESOLVE_ALERT' && l.entityId === targetId)
    );

    // 5. Sign in as Demo Administrator -> allowed to update sensitivity & retrain ML
    const adminLogin = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'admin-demo-2026' }),
    });
    assert.equal(adminLogin.status, 200);
    const { token: adminToken } = (await adminLogin.json()) as { token: string };

    const adminOk = await fetch(`${baseUrl}/api/settings/sensitivity`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({ level: 'high' }),
    });
    assert.equal(adminOk.status, 200);

    // Restore balanced sensitivity for subsequent tests
    const resetSens = await fetch(`${baseUrl}/api/settings/sensitivity`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({ level: 'balanced' }),
    });
    assert.equal(resetSens.status, 200);
  });

  test('exports real filtered CSV and JSON reports with forensic scope', async () => {
    const csvRes = await fetch(`${baseUrl}/api/reports/export?format=csv&severity=Critical&scope=incidents`);
    assert.equal(csvRes.status, 200);
    assert.ok(csvRes.headers.get('content-type')?.includes('text/csv'));
    const csvText = await csvRes.text();
    assert.ok(csvText.includes('Alert ID,Timestamp,Severity'));
    assert.ok(csvText.includes('Critical'));

    const jsonRes = await fetch(`${baseUrl}/api/reports/export?format=json&scope=forensics`);
    assert.equal(jsonRes.status, 200);
    const jsonData = (await jsonRes.json()) as {
      platform: string;
      scope: string;
      alerts: unknown[];
      forensicCases: unknown[];
    };
    assert.equal(jsonData.platform, 'SENTINELFORGE');
    assert.equal(jsonData.scope, 'forensics');
    assert.ok(Array.isArray(jsonData.alerts) && jsonData.alerts.length > 0);
    assert.ok(Array.isArray(jsonData.forensicCases) && jsonData.forensicCases.length > 0);
  });
});

describe('SentinelForge Log Analyzer Ingestion, Deduplication & Threat Consistency', () => {
  let tmpDir: string;
  let baseUrl: string;
  let serverHandle: ReturnType<import('express').Express['listen']>;

  before(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinelforge-ingest-'));
    const { app } = await createServer({ dataDir: tmpDir, skipVite: true });
    await new Promise<void>((resolve) => {
      serverHandle = app.listen(0, '127.0.0.1', () => {
        const addr = serverHandle.address();
        if (addr && typeof addr === 'object') {
          baseUrl = `http://127.0.0.1:${addr.port}`;
        }
        resolve();
      });
    });
  });

  after(async () => {
    await new Promise<void>((resolve) => serverHandle.close(() => resolve()));
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('sample_auth_logs.csv consistently flags 4 threats and repeated imports prevent duplicates while preserving triage', async () => {
    const baselineDash = (await (await fetch(`${baseUrl}/api/dashboard`)).json()) as {
      totalEvents: number;
      totalThreats: number;
    };
    const baselineAlerts = (await (await fetch(`${baseUrl}/api/alerts`)).json()) as {
      alerts: Array<{ id: string; category: string; datasetKey?: string; status: string }>;
    };

    const sampleAuthAlerts = baselineAlerts.alerts.filter((a) => a.datasetKey === 'sample_auth_logs.csv');
    assert.equal(sampleAuthAlerts.length, 4);
    assert.deepEqual(
      sampleAuthAlerts.map((a) => a.category).sort(),
      ['Brute Force', 'Malware Indicators', 'Privilege Escalation', 'Suspicious Authentication']
    );

    // Triage one alert from sample_auth_logs.csv to verify triage is preserved across re-import
    const targetAuthAlert = sampleAuthAlerts[0];
    const patchRes = await fetch(`${baseUrl}/api/alerts/${targetAuthAlert.id}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: 'acknowledged' }),
    });
    assert.equal(patchRes.status, 200);

    // Re-load via sample endpoint
    const sampleRes = await fetch(`${baseUrl}/api/logs/sample/bruteforce_lateral_csv`, { method: 'POST' });
    assert.equal(sampleRes.status, 201);
    const sampleBody = (await sampleRes.json()) as {
      newEventsCount: number;
      newAlertsCount: number;
      replacedExisting: boolean;
      upload: { validCount: number; invalidCount: number; threatsDetected: number; importCount: number };
      alerts: Array<{ category: string }>;
    };
    assert.equal(sampleBody.replacedExisting, true);
    assert.equal(sampleBody.newEventsCount, 14);
    assert.equal(sampleBody.newAlertsCount, 4);
    assert.equal(sampleBody.upload.validCount, 14);
    assert.equal(sampleBody.upload.invalidCount, 0);
    assert.equal(sampleBody.upload.threatsDetected, 4);
    assert.equal(sampleBody.upload.importCount, 2);

    // Re-upload the actual sample_auth_logs.csv file directly
    const csvContent = fs.readFileSync(path.join(process.cwd(), 'samples', 'sample_auth_logs.csv'), 'utf8');
    const uploadRes = await fetch(`${baseUrl}/api/logs/upload`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename: 'sample_auth_logs.csv', content: csvContent, format: 'csv' }),
    });
    assert.equal(uploadRes.status, 201);
    const uploadBody = (await uploadRes.json()) as {
      newEventsCount: number;
      newAlertsCount: number;
      replacedExisting: boolean;
      upload: { validCount: number; invalidCount: number; threatsDetected: number; importCount: number };
    };
    assert.equal(uploadBody.replacedExisting, true);
    assert.equal(uploadBody.newEventsCount, 14);
    assert.equal(uploadBody.newAlertsCount, 4);
    assert.equal(uploadBody.upload.threatsDetected, 4);
    assert.equal(uploadBody.upload.importCount, 3);

    // Dashboard totals must NOT have duplicated events or alerts
    const afterDash = (await (await fetch(`${baseUrl}/api/dashboard`)).json()) as {
      totalEvents: number;
      totalThreats: number;
    };
    assert.equal(afterDash.totalEvents, baselineDash.totalEvents);
    assert.equal(afterDash.totalThreats, baselineDash.totalThreats);

    // Preserved triage & unrelated firewall alerts remain intact
    const afterAlerts = (await (await fetch(`${baseUrl}/api/alerts`)).json()) as {
      alerts: Array<{ id: string; datasetKey?: string; status: string }>;
    };
    const preservedAuth = afterAlerts.alerts.find((a) => a.id === targetAuthAlert.id);
    assert.equal(preservedAuth?.status, 'acknowledged');
    const firewallAlerts = afterAlerts.alerts.filter((a) => a.datasetKey === 'sample_firewall_events.json');
    assert.equal(firewallAlerts.length, 2);
  });

  test('validates CSV/JSON/TXT mixed files, excludes malformed rows from normalized records, and preserves prior detections', async () => {
    const beforeDash = (await (await fetch(`${baseUrl}/api/dashboard`)).json()) as {
      totalEvents: number;
      totalThreats: number;
    };

    // 1. Mixed CSV with 5 valid brute-force rows and 2 malformed/incomplete rows
    const mixedCsv = [
      'timestamp,source_ip,destination_ip,destination_port,protocol,username,event_type,action,status_code,message',
      '2026-11-22T02:00:01Z,203.0.113.200,10.0.1.50,22,TCP,root,AUTH_FAILURE,FAILED,401,Failed password for root',
      '2026-11-22T02:00:02Z,203.0.113.200,10.0.1.50,22,TCP,root,AUTH_FAILURE,FAILED,401,Failed password for root',
      '2026-11-22T02:00:03Z,203.0.113.200,10.0.1.50,22,TCP,admin,AUTH_FAILURE,FAILED,401,Failed password for admin',
      '2026-11-22T02:00:04Z,203.0.113.200,10.0.1.50,22,TCP,ubuntu,AUTH_FAILURE,FAILED,401,Failed password for ubuntu',
      '2026-11-22T02:00:05Z,203.0.113.200,10.0.1.50,22,TCP,deploy,AUTH_FAILURE,FAILED,401,Failed password for deploy',
      '2026-11-22T02:00:06Z,203.0.113.200,10.0.1.50',
      'bad-time,999.1.1.1,10.0.1.50,22,TCP,root,AUTH_FAILURE,FAILED,401,Invalid row',
    ].join('\n');

    const csvRes = await fetch(`${baseUrl}/api/logs/upload`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename: 'mixed_batch.csv', content: mixedCsv, format: 'csv' }),
    });
    assert.equal(csvRes.status, 201);
    const csvBody = (await csvRes.json()) as {
      newEventsCount: number;
      newAlertsCount: number;
      upload: { validCount: number; invalidCount: number; threatsDetected: number; validationErrors: unknown[] };
    };
    assert.equal(csvBody.newEventsCount, 5);
    assert.equal(csvBody.upload.validCount, 5);
    assert.equal(csvBody.upload.invalidCount, 2);
    assert.equal(csvBody.upload.validationErrors.length, 2);
    assert.ok(csvBody.newAlertsCount >= 1);
    assert.equal(csvBody.upload.threatsDetected, csvBody.newAlertsCount);

    // 2. Mixed JSON with 2 valid malware records + 2 invalid records
    const mixedJson = JSON.stringify([
      {
        timestamp: '2026-11-22T03:10:00Z',
        sourceIp: '198.51.100.201',
        destinationIp: '10.0.1.60',
        destinationPort: 4444,
        protocol: 'TCP',
        username: 'svc-app',
        eventType: 'MALWARE_SIGNAL',
        action: 'BLOCKED',
        statusCode: 403,
        message: 'Outbound reverse_shell beacon blocked',
      },
      {
        timestamp: '2026-11-22T03:10:05Z',
        sourceIp: '10.0.2.15',
        destinationIp: '10.0.1.10',
        destinationPort: 443,
        protocol: 'TCP',
        username: 'alice.chen',
        eventType: 'FIREWALL',
        action: 'ALLOW',
        statusCode: 200,
        message: 'Normal HTTPS traffic',
      },
      { timestamp: 'invalid', sourceIp: '198.51.100.201', message: 'Bad ts' },
      { timestamp: '2026-11-22T03:10:09Z', sourceIp: 'not-an-ip', message: 'Bad ip' },
    ]);

    const jsonRes = await fetch(`${baseUrl}/api/logs/upload`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename: 'mixed_edr.json', content: mixedJson, format: 'json' }),
    });
    assert.equal(jsonRes.status, 201);
    const jsonBody = (await jsonRes.json()) as {
      newEventsCount: number;
      newAlertsCount: number;
      upload: { validCount: number; invalidCount: number; threatsDetected: number };
    };
    assert.equal(jsonBody.newEventsCount, 2);
    assert.equal(jsonBody.upload.validCount, 2);
    assert.equal(jsonBody.upload.invalidCount, 2);
    assert.equal(jsonBody.newAlertsCount, 1);

    // 3. TXT syslog ingestion via bundled sample + invalid lines
    const txtSample = fs.readFileSync(path.join(process.cwd(), 'samples', 'sample_ssh_syslog.txt'), 'utf8');
    const mixedTxt = `${txtSample}\nmalformed line without timestamp 10.0.0.1\n2026-11-22T01:25:00Z missing_ip only_text`;
    const txtRes = await fetch(`${baseUrl}/api/logs/upload`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename: 'mixed_ssh.txt', content: mixedTxt, format: 'txt' }),
    });
    assert.equal(txtRes.status, 201);
    const txtBody = (await txtRes.json()) as {
      newEventsCount: number;
      newAlertsCount: number;
      upload: { validCount: number; invalidCount: number; threatsDetected: number };
    };
    assert.equal(txtBody.newEventsCount, 8);
    assert.equal(txtBody.upload.validCount, 8);
    assert.equal(txtBody.upload.invalidCount, 2);
    assert.equal(txtBody.newAlertsCount, 2);

    // 4. Completely invalid payload fails with 422 and preserves prior totals
    const badRes = await fetch(`${baseUrl}/api/logs/upload`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename: 'broken.json', content: '{ bad json', format: 'json' }),
    });
    assert.equal(badRes.status, 422);

    // Verify all counts in dataset history and overall store remain accurate and additive across distinct datasets
    const logsRes = await fetch(`${baseUrl}/api/logs`);
    const logsData = (await logsRes.json()) as {
      totalCount: number;
      uploads: Array<{ filename: string; validCount: number; invalidCount: number; threatsDetected: number }>;
    };
    assert.equal(logsData.totalCount, beforeDash.totalEvents + 5 + 2 + 8);
    assert.equal(logsData.uploads[0].filename, 'broken.json');
    assert.equal(logsData.uploads[0].validCount, 0);
    assert.equal(logsData.uploads[0].threatsDetected, 0);

    const afterDash = (await (await fetch(`${baseUrl}/api/dashboard`)).json()) as {
      totalEvents: number;
      totalThreats: number;
    };
    assert.equal(
      afterDash.totalThreats,
      beforeDash.totalThreats + csvBody.newAlertsCount + jsonBody.newAlertsCount + txtBody.newAlertsCount
    );
  });
});

