import type {
  AttackSequence,
  AuditLogEntry,
  DashboardSummary,
  DatasetUploadRecord,
  ForensicCase,
  MLEvaluationReport,
  PublicUser,
  SecurityEvent,
  SensitivityConfig,
  SensitivityLevel,
  ThreatAlert,
  ThreatIntelRecord,
} from '../shared/types';

let inMemoryToken: string | null = null;

export function setAuthToken(token: string | null): void {
  inMemoryToken = token;
}

export function getAuthToken(): string | null {
  return inMemoryToken;
}

export class ApiError extends Error {
  status: number;
  upload?: DatasetUploadRecord;
  constructor(status: number, message: string, upload?: DatasetUploadRecord) {
    super(message);
    this.status = status;
    this.upload = upload;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...((init?.headers as Record<string, string>) ?? {}),
  };
  if (inMemoryToken) {
    headers.Authorization = `Bearer ${inMemoryToken}`;
  }

  const res = await fetch(path, {
    ...init,
    headers,
  });

  if (!res.ok) {
    let msg = `Request failed (${res.status})`;
    let upload: DatasetUploadRecord | undefined;
    try {
      const body = (await res.json()) as { error?: string; upload?: DatasetUploadRecord };
      if (body.error) msg = body.error;
      if (body.upload) upload = body.upload;
    } catch {
      // ignore non-json error body
    }
    throw new ApiError(res.status, msg, upload);
  }

  return (await res.json()) as T;
}

export const api = {
  getDashboard: () => request<DashboardSummary>('/api/dashboard'),

  getLogs: (params?: { q?: string; action?: string }) => {
    const qs = new URLSearchParams();
    if (params?.q) qs.set('q', params.q);
    if (params?.action) qs.set('action', params.action);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return request<{
      events: SecurityEvent[];
      totalCount: number;
      uploads: DatasetUploadRecord[];
      samples: Array<{
        key: string;
        name: string;
        filename: string;
        format: 'csv' | 'json' | 'txt';
        description: string;
      }>;
    }>(`/api/logs${suffix}`);
  },

  uploadLogs: (payload: { filename: string; content: string; format?: 'csv' | 'json' | 'txt' }) =>
    request<{
      upload: DatasetUploadRecord;
      newEventsCount: number;
      newAlertsCount: number;
      replacedExisting?: boolean;
      totalEventsInStore?: number;
      totalAlertsInStore?: number;
      alerts: ThreatAlert[];
    }>('/api/logs/upload', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  loadSampleLogs: (sampleKey: string) =>
    request<{
      upload: DatasetUploadRecord;
      newEventsCount: number;
      newAlertsCount: number;
      replacedExisting?: boolean;
      totalEventsInStore?: number;
      totalAlertsInStore?: number;
      alerts: ThreatAlert[];
    }>(`/api/logs/sample/${encodeURIComponent(sampleKey)}`, {
      method: 'POST',
    }),

  getAlerts: (params?: { q?: string; severity?: string; status?: string; category?: string }) => {
    const qs = new URLSearchParams();
    if (params?.q) qs.set('q', params.q);
    if (params?.severity) qs.set('severity', params.severity);
    if (params?.status) qs.set('status', params.status);
    if (params?.category) qs.set('category', params.category);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return request<{ alerts: ThreatAlert[]; total: number }>(`/api/alerts${suffix}`);
  },

  updateAlertStatus: (id: string, status: 'open' | 'acknowledged' | 'resolved') =>
    request<{ alert: ThreatAlert }>(`/api/alerts/${encodeURIComponent(id)}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    }),

  submitAlertFeedback: (id: string, feedback: 'true_positive' | 'false_positive') =>
    request<{ alert: ThreatAlert }>(`/api/alerts/${encodeURIComponent(id)}/feedback`, {
      method: 'POST',
      body: JSON.stringify({ feedback }),
    }),

  getCorrelations: () => request<{ sequences: AttackSequence[] }>('/api/correlations'),

  getForensics: () => request<{ cases: ForensicCase[] }>('/api/forensics'),

  createForensicCaseFromAlert: (alertId: string) =>
    request<{ forensicCase: ForensicCase }>(`/api/forensics/from-alert/${encodeURIComponent(alertId)}`, {
      method: 'POST',
    }),

  addForensicNote: (caseId: string, content: string, status?: 'investigating' | 'contained' | 'closed') =>
    request<{ forensicCase: ForensicCase }>(`/api/forensics/${encodeURIComponent(caseId)}/notes`, {
      method: 'POST',
      body: JSON.stringify({ content, status }),
    }),

  getIntel: () => request<{ records: ThreatIntelRecord[] }>('/api/intel'),

  lookupIntel: (ip: string, includePublicFeed: boolean) =>
    request<{
      record: ThreatIntelRecord;
      lookupStatus: 'verified_live' | 'blocked_private' | 'invalid_ip' | 'offline_fallback' | 'local_only';
      statusDetail: string;
    }>('/api/intel/lookup', {
      method: 'POST',
      body: JSON.stringify({ ip, includePublicFeed }),
    }),

  getMlEvaluation: () =>
    request<{
      evaluation: MLEvaluationReport;
      datasetPreview: Array<{
        id: string;
        timestamp: string;
        sourceIp: string;
        port: number;
        category: string;
        label: 0 | 1;
      }>;
    }>('/api/ml/evaluation'),

  retrainModels: (payload: { splitRatio: number; seed: number; includeFeedback: boolean }) =>
    request<{ evaluation: MLEvaluationReport }>('/api/ml/retrain', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  getAuditLogs: (action?: string) => {
    const qs = action && action !== 'ALL' ? `?action=${encodeURIComponent(action)}` : '';
    return request<{ auditLogs: AuditLogEntry[] }>(`/api/audit${qs}`);
  },

  getSettings: () =>
    request<{
      sensitivity: SensitivityConfig;
      splitRatio: number;
      seed: number;
      eventsCount: number;
      alertsCount: number;
    }>('/api/settings'),

  updateSensitivity: (level: SensitivityLevel) =>
    request<{ sensitivity: SensitivityConfig }>('/api/settings/sensitivity', {
      method: 'PATCH',
      body: JSON.stringify({ level }),
    }),

  resetDemoData: () =>
    request<{ message: string; eventsCount: number; alertsCount: number }>('/api/system/reset', {
      method: 'POST',
    }),

  getDocs: () =>
    request<{
      version: string;
      baseUrl: string;
      authScheme: string;
      endpoints: Array<{ method: string; path: string; role: string; description: string }>;
    }>('/api/docs'),

  login: (username: string, password: string) =>
    request<{ token: string; user: PublicUser }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),

  register: (username: string, password: string, displayName: string) =>
    request<{ token: string; user: PublicUser }>('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ username, password, displayName }),
    }),
};
