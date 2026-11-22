export type UserRole = 'analyst' | 'administrator';

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low';

export type ThreatCategory =
  | 'Brute Force'
  | 'Port Scanning'
  | 'Suspicious Authentication'
  | 'Privilege Escalation'
  | 'Malware Indicators'
  | 'Unusual Network Activity'
  | 'Other Suspicious Behavior'
  | 'Benign';

export type AlertStatus = 'open' | 'acknowledged' | 'resolved';

export type AnalystFeedback = 'unreviewed' | 'true_positive' | 'false_positive';

export type SensitivityLevel = 'low' | 'balanced' | 'high';

export interface MitreMapping {
  tacticId: string;
  tacticName: string;
  techniqueId: string;
  techniqueName: string;
  url: string;
}

export interface FeatureContribution {
  featureName: string;
  label: string;
  rawValue: number;
  normalizedValue: number;
  weight: number;
  contribution: number;
  direction: 'threat' | 'benign';
}

export interface XAIExplanation {
  reasons: string[];
  ruleTriggers: string[];
  isolationForestScore: number;
  isolationAvgPathLength: number;
  logisticRegressionProb: number;
  statisticalZScore: number;
  ensembleScore: number;
  featureContributions: FeatureContribution[];
}

export interface EventFeatures {
  failedAuthCountIp: number;
  distinctPortsIp: number;
  ipEventBurstCount: number;
  isOffHours: number;
  privilegeKeywordScore: number;
  malwareKeywordScore: number;
  suspiciousPortScore: number;
  isPublicSourceIp: number;
  isFailureStatus: number;
  interArrivalZScore: number;
}

export interface SecurityEvent {
  id: string;
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
  sourceFile: string;
  datasetKey?: string;
  contentHash?: string;
  isDemoData: boolean;
  groundTruthLabel?: 0 | 1;
  features: EventFeatures;
}

export interface ThreatAlert {
  id: string;
  eventIds: string[];
  primaryEventId: string;
  timestamp: string;
  sourceIp: string;
  destinationIp: string;
  username: string;
  title: string;
  description: string;
  category: Exclude<ThreatCategory, 'Benign'>;
  severity: Severity;
  confidence: number;
  ruleScore: number;
  mlProbability: number;
  anomalyScore: number;
  status: AlertStatus;
  analystFeedback: AnalystFeedback;
  mitre: MitreMapping;
  xai: XAIExplanation;
  recommendations: string[];
  isDemoData: boolean;
  datasetKey?: string;
  contentHash?: string;
  acknowledgedBy?: string;
  acknowledgedAt?: string;
  resolvedBy?: string;
  resolvedAt?: string;
  lastModifiedBy?: string;
  lastModifiedAt?: string;
}

export interface AttackStage {
  order: number;
  timestamp: string;
  alertId: string;
  category: Exclude<ThreatCategory, 'Benign'>;
  mitreTactic: string;
  mitreTechnique: string;
  summary: string;
  severity: Severity;
}

export interface AttackSequence {
  id: string;
  sourceIp: string;
  targetUsers: string[];
  startTime: string;
  endTime: string;
  stageCount: number;
  overallSeverity: Severity;
  riskScore: number;
  narrative: string;
  stages: AttackStage[];
  isDemoData: boolean;
}

export interface ForensicNote {
  id: string;
  author: string;
  authorRole: UserRole | 'guest_demo';
  timestamp: string;
  content: string;
}

export interface ForensicCase {
  id: string;
  alertId: string;
  title: string;
  severity: Severity;
  sourceIp: string;
  status: 'investigating' | 'contained' | 'closed';
  evidenceSha256: string;
  evidenceSummary: string;
  rawArtifacts: string[];
  timeline: Array<{
    timestamp: string;
    event: string;
    actor: string;
  }>;
  notes: ForensicNote[];
  createdAt: string;
  updatedAt: string;
  isDemoData: boolean;
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  actorUsername: string;
  actorRole: UserRole | 'guest_demo' | 'system';
  action: string;
  entityType: 'alert' | 'forensic_case' | 'dataset' | 'ml_model' | 'settings' | 'auth' | 'system';
  entityId: string;
  summary: string;
  previousValue?: string;
  newValue?: string;
}

export interface ThreatIntelRecord {
  ip: string;
  ipVersion: 'IPv4' | 'IPv6' | 'Invalid';
  scope: 'Private / Reserved' | 'Public Routable' | 'Invalid';
  cidrClass: string;
  provenance: 'Demo Intelligence' | 'Verified Public Feed' | 'Local Classifier Only';
  reputation: 'Malicious' | 'Suspicious' | 'Benign' | 'Unknown';
  riskScore: number;
  asnOrOwner: string;
  country: string;
  tags: string[];
  summary: string;
  checkedAt: string;
}

export interface ConfusionMatrix {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
}

export interface ModelMetrics {
  modelName: string;
  accuracy: number;
  precision: number;
  recall: number;
  f1Score: number;
  falsePositiveRate: number;
  confusionMatrix: ConfusionMatrix;
}

export interface MLEvaluationReport {
  evaluatedAt: string;
  seed: number;
  splitRatio: number;
  totalDatasetRecords: number;
  trainCount: number;
  testCount: number;
  trainThreatCount: number;
  testThreatCount: number;
  feedbackSamplesIncluded: number;
  preprocessingSummary: {
    scalerMethod: string;
    leakagePrevention: string;
    featureCount: number;
    featureNames: string[];
  };
  isolationForest: ModelMetrics;
  logisticRegression: ModelMetrics;
  hybridEnsemble: ModelMetrics;
  learnedWeights: Array<{
    feature: string;
    label: string;
    weight: number;
    absWeight: number;
  }>;
}

export interface DatasetValidationError {
  line: number;
  raw: string;
  reason: string;
}

export interface DatasetUploadRecord {
  id: string;
  filename: string;
  datasetKey?: string;
  contentHash?: string;
  format: 'csv' | 'json' | 'txt';
  uploadedAt: string;
  uploadedBy: string;
  totalLines: number;
  validCount: number;
  invalidCount: number;
  threatsDetected: number;
  replacedPrevious?: boolean;
  importCount?: number;
  validationErrors: DatasetValidationError[];
}

export interface SensitivityConfig {
  level: SensitivityLevel;
  anomalyThreshold: number;
  mlProbabilityThreshold: number;
  ruleAlertThreshold: number;
  bruteForceThreshold: number;
  portScanThreshold: number;
}

export interface PublicUser {
  id: string;
  username: string;
  displayName: string;
  role: UserRole;
  isDemoAccount: boolean;
}

export interface DashboardSummary {
  totalEvents: number;
  totalThreats: number;
  openAlerts: number;
  acknowledgedAlerts: number;
  resolvedAlerts: number;
  severityCounts: Record<Severity, number>;
  categoryDistribution: Array<{ category: string; count: number }>;
  trendSeries: Array<{
    bucket: string;
    events: number;
    threats: number;
  }>;
  topSuspiciousIps: Array<{
    ip: string;
    alertCount: number;
    maxSeverity: Severity;
    avgScore: number;
    isPublic: boolean;
  }>;
  recentAlerts: ThreatAlert[];
  recentActivity: AuditLogEntry[];
  correlatedSequencesCount: number;
}
