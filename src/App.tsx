import React, { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  BarChart3,
  BookOpen,
  ClipboardList,
  Cpu,
  FileSearch,
  FileText,
  GitBranch,
  Globe,
  LayoutDashboard,
  Menu,
  Settings,
  ShieldAlert,
  UserCheck,
  X,
} from 'lucide-react';
import { AuthModal } from './components/AuthModal';
import { BrandLogo } from './components/BrandLogo';
import { api } from './lib/api';
import type { DashboardSummary, PublicUser } from './shared/types';
import { AlertsView } from './views/AlertsView';
import { AnalyticsView } from './views/AnalyticsView';
import { ApiDocsView } from './views/ApiDocsView';
import { AuditView } from './views/AuditView';
import { CorrelationView } from './views/CorrelationView';
import { DashboardView } from './views/DashboardView';
import { ForensicsView } from './views/ForensicsView';
import { LogAnalyzerView } from './views/LogAnalyzerView';
import { MLEvaluationView } from './views/MLEvaluationView';
import { ReportsView } from './views/ReportsView';
import { SettingsView } from './views/SettingsView';
import { ThreatIntelView } from './views/ThreatIntelView';

type NavKey =
  | 'dashboard'
  | 'logs'
  | 'alerts'
  | 'correlations'
  | 'ml'
  | 'forensics'
  | 'intel'
  | 'analytics'
  | 'reports'
  | 'audit'
  | 'settings'
  | 'docs';

const NAV_ITEMS: Array<{ key: NavKey; label: string; icon: React.ComponentType<{ className?: string }> }> = [
  { key: 'dashboard', label: 'Security Dashboard', icon: LayoutDashboard },
  { key: 'logs', label: 'Log Analyzer', icon: Activity },
  { key: 'alerts', label: 'Alerts & XAI', icon: ShieldAlert },
  { key: 'correlations', label: 'Attack Correlation', icon: GitBranch },
  { key: 'ml', label: 'ML Evaluation Lab', icon: Cpu },
  { key: 'forensics', label: 'Digital Forensics', icon: FileSearch },
  { key: 'intel', label: 'Threat Intelligence', icon: Globe },
  { key: 'analytics', label: 'Security Analytics', icon: BarChart3 },
  { key: 'reports', label: 'Incident Reports', icon: FileText },
  { key: 'audit', label: 'Audit Trail', icon: ClipboardList },
  { key: 'settings', label: 'Settings', icon: Settings },
  { key: 'docs', label: 'API Docs & Tests', icon: BookOpen },
];

export default function App() {
  const [activeNav, setActiveNav] = useState<NavKey>('dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [dashboard, setDashboard] = useState<DashboardSummary | null>(null);
  const [dashLoading, setDashLoading] = useState(true);
  const [dashError, setDashError] = useState<string | null>(null);

  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [selectedForensicCaseId, setSelectedForensicCaseId] = useState<string | null>(null);

  const [currentUser, setCurrentUser] = useState<PublicUser | null>(null);
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [compactDensity, setCompactDensity] = useState(false);

  const fetchDashboard = useCallback(async () => {
    setDashLoading(true);
    setDashError(null);
    try {
      const data = await api.getDashboard();
      setDashboard(data);
    } catch (err) {
      setDashError(err instanceof Error ? err.message : 'Unable to reach SentinelForge API');
    } finally {
      setDashLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchDashboard();
  }, [fetchDashboard]);

  const handleNavigate = (view: string, options?: { alertId?: string; caseId?: string }) => {
    const key = view as NavKey;
    if (options?.alertId) setSelectedAlertId(options.alertId);
    if (options?.caseId) setSelectedForensicCaseId(options.caseId);
    setActiveNav(key);
    setSidebarOpen(false);
  };

  const activeNavMeta = NAV_ITEMS.find((n) => n.key === activeNav) ?? NAV_ITEMS[0];

  return (
    <div className="flex min-h-screen bg-[#060913] text-slate-100">
      {/* Mobile Sidebar Backdrop */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/60 lg:hidden"
          onClick={() => setSidebarOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Left Sidebar Navigation */}
      <aside
        className={`no-print fixed inset-y-0 left-0 z-40 flex w-64 shrink-0 flex-col border-r border-slate-800 bg-[#0B1120] transition-transform duration-150 lg:static lg:translate-x-0 ${
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
          <div className="flex items-center gap-3">
            <BrandLogo size={30} />
            <div>
              <div className="text-sm font-bold tracking-wide text-slate-100">SENTINELFORGE</div>
              <div className="text-[11px] text-slate-400">AI Threat Detection</div>
            </div>
          </div>
          <button
            type="button"
            onClick={() => setSidebarOpen(false)}
            className="rounded p-1 text-slate-400 hover:bg-slate-800 lg:hidden"
            aria-label="Close navigation"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <nav className="flex-1 space-y-0.5 overflow-y-auto px-3 py-4" aria-label="SOC Modules">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const active = activeNav === item.key;
            return (
              <button
                key={item.key}
                type="button"
                onClick={() => handleNavigate(item.key)}
                className={`flex w-full items-center justify-between px-3 py-2 text-left text-xs font-medium transition-colors whitespace-nowrap ${
                  active
                    ? 'bg-blue-600/15 text-blue-300'
                    : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-100'
                }`}
              >
                <span className="flex items-center gap-2.5 truncate">
                  <Icon className={`h-4 w-4 shrink-0 ${active ? 'text-blue-400' : 'text-slate-500'}`} />
                  <span className="truncate">{item.label}</span>
                </span>
                {item.key === 'alerts' && dashboard && dashboard.openAlerts > 0 && (
                  <span className="font-mono text-[11px] text-red-400 tabular-nums">{dashboard.openAlerts}</span>
                )}
              </button>
            );
          })}
        </nav>

        <div className="border-t border-slate-800 p-4 text-[11px] text-slate-400">
          <div className="font-medium text-slate-300">Local-First Defensive SOC</div>
          <div className="mt-0.5 text-slate-500">
            Session:{' '}
            <span className="font-mono text-slate-300">
              {currentUser ? `${currentUser.username} (${currentUser.role})` : 'Demo Guest'}
            </span>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex min-w-0 flex-1 flex-col">
        {/* Top Bar */}
        <header className="no-print flex items-center justify-between gap-4 border-b border-slate-800 bg-[#0B1120] px-6 py-3.5">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setSidebarOpen(true)}
              className="rounded border border-slate-700 p-1.5 text-slate-300 hover:bg-slate-800 lg:hidden"
              aria-label="Open navigation"
            >
              <Menu className="h-4 w-4" />
            </button>
            <div className="truncate text-xs text-slate-400">
              <span className="font-semibold text-slate-200">SENTINELFORGE</span>
              <span className="mx-2 text-slate-600">/</span>
              <span>{activeNavMeta.label}</span>
            </div>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <button
              type="button"
              onClick={() => setAuthModalOpen(true)}
              className="inline-flex items-center gap-2 border border-slate-700 bg-[#111827] px-3.5 py-1.5 text-xs font-medium text-slate-200 hover:border-blue-500/60 hover:text-white whitespace-nowrap shrink-0"
            >
              <UserCheck className="h-3.5 w-3.5 text-blue-400" />
              <span>
                {currentUser ? `${currentUser.username} (${currentUser.role})` : 'Demo Sign-In'}
              </span>
            </button>
          </div>
        </header>

        {/* Active Module Viewport */}
        <main className={`mx-auto w-full max-w-[1440px] flex-1 ${compactDensity ? 'p-4' : 'p-6 lg:p-8'}`}>
          {activeNav === 'dashboard' && (
            <DashboardView
              data={dashboard}
              loading={dashLoading}
              error={dashError}
              onRefresh={() => void fetchDashboard()}
              onNavigate={(v, opts) => handleNavigate(v, opts)}
            />
          )}

          {activeNav === 'logs' && (
            <LogAnalyzerView
              onAnalyzed={() => void fetchDashboard()}
              onNavigateAlerts={() => handleNavigate('alerts')}
            />
          )}

          {activeNav === 'alerts' && (
            <AlertsView
              initialSelectedId={selectedAlertId}
              onChanged={() => void fetchDashboard()}
              onOpenForensicsCase={(caseId) => handleNavigate('forensics', { caseId })}
            />
          )}

          {activeNav === 'correlations' && (
            <CorrelationView
              onSelectAlert={(alertId) => handleNavigate('alerts', { alertId })}
            />
          )}

          {activeNav === 'ml' && (
            <MLEvaluationView
              currentUser={currentUser}
              onRequireAuth={() => setAuthModalOpen(true)}
            />
          )}

          {activeNav === 'forensics' && (
            <ForensicsView
              initialCaseId={selectedForensicCaseId}
              onChanged={() => void fetchDashboard()}
            />
          )}

          {activeNav === 'intel' && <ThreatIntelView />}

          {activeNav === 'analytics' && <AnalyticsView />}

          {activeNav === 'reports' && <ReportsView />}

          {activeNav === 'audit' && <AuditView />}

          {activeNav === 'settings' && (
            <SettingsView
              currentUser={currentUser}
              compactDensity={compactDensity}
              onToggleCompact={setCompactDensity}
              onRequireAuth={() => setAuthModalOpen(true)}
              onDataReset={() => void fetchDashboard()}
            />
          )}

          {activeNav === 'docs' && <ApiDocsView />}
        </main>
      </div>

      <AuthModal
        open={authModalOpen}
        onClose={() => setAuthModalOpen(false)}
        currentUser={currentUser}
        onAuthenticated={(user) => {
          setCurrentUser(user);
          void fetchDashboard();
        }}
      />
    </div>
  );
}
