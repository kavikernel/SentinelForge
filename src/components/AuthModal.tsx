import React, { useState } from 'react';
import { Lock, Shield, UserCheck, X } from 'lucide-react';
import { api, setAuthToken } from '../lib/api';
import type { PublicUser } from '../shared/types';

interface AuthModalProps {
  open: boolean;
  onClose: () => void;
  currentUser: PublicUser | null;
  onAuthenticated: (user: PublicUser | null) => void;
}

export const AuthModal: React.FC<AuthModalProps> = ({ open, onClose, currentUser, onAuthenticated }) => {
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [username, setUsername] = useState('analyst');
  const [password, setPassword] = useState('analyst-demo-2026');
  const [displayName, setDisplayName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!open) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const res =
        mode === 'login'
          ? await api.login(username, password)
          : await api.register(username, password, displayName);
      setAuthToken(res.token);
      onAuthenticated(res.user);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  const quickLogin = async (role: 'analyst' | 'admin') => {
    const u = role === 'admin' ? 'admin' : 'analyst';
    const p = role === 'admin' ? 'admin-demo-2026' : 'analyst-demo-2026';
    setUsername(u);
    setPassword(p);
    setLoading(true);
    setError(null);
    try {
      const res = await api.login(u, p);
      setAuthToken(res.token);
      onAuthenticated(res.user);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  const handleSignOut = () => {
    setAuthToken(null);
    onAuthenticated(null);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4" role="dialog" aria-modal="true" aria-label="Demo Analyst Authentication">
      <div className="w-full max-w-md border border-slate-800 bg-[#0B1120] p-6">
        <div className="flex items-start justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <h2 className="text-lg font-semibold text-slate-100">Demo Authentication &amp; Role Access</h2>
            <p className="mt-1 text-xs text-slate-400">
              Local demonstration authentication only. Not intended for production identity management.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded p-1.5 text-slate-400 hover:bg-slate-800 hover:text-slate-100 focus-visible:outline-2 focus-visible:outline-blue-500"
            aria-label="Close dialog"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {currentUser && (
          <div className="mt-4 flex items-center justify-between border border-slate-800 bg-[#111827] px-4 py-3 text-xs">
            <div>
              <div className="font-medium text-slate-100">{currentUser.displayName}</div>
              <div className="mt-0.5 text-slate-400">
                Role: <span className="font-mono text-blue-400">{currentUser.role}</span> · Demo Session
              </div>
            </div>
            <button
              type="button"
              onClick={handleSignOut}
              className="border border-slate-700 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800"
            >
              Sign Out
            </button>
          </div>
        )}

        <div className="mt-4 grid grid-cols-2 gap-2">
          <button
            type="button"
            disabled={loading}
            onClick={() => void quickLogin('analyst')}
            className="flex items-center justify-center gap-2 border border-slate-700 bg-[#111827] px-3 py-2 text-xs font-medium text-slate-200 hover:border-blue-500/60 hover:text-white"
          >
            <UserCheck className="h-3.5 w-3.5 text-blue-400" />
            <span>Demo Analyst</span>
          </button>
          <button
            type="button"
            disabled={loading}
            onClick={() => void quickLogin('admin')}
            className="flex items-center justify-center gap-2 border border-slate-700 bg-[#111827] px-3 py-2 text-xs font-medium text-slate-200 hover:border-violet-500/60 hover:text-white"
          >
            <Shield className="h-3.5 w-3.5 text-violet-400" />
            <span>Demo Administrator</span>
          </button>
        </div>

        <div className="mt-5 flex border-b border-slate-800 text-xs">
          <button
            type="button"
            onClick={() => {
              setMode('login');
              setError(null);
            }}
            className={`px-4 py-2 font-medium transition-colors ${
              mode === 'login' ? 'border-b-2 border-blue-500 text-blue-400' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Sign In
          </button>
          <button
            type="button"
            onClick={() => {
              setMode('register');
              setUsername('');
              setPassword('');
              setError(null);
            }}
            className={`px-4 py-2 font-medium transition-colors ${
              mode === 'register' ? 'border-b-2 border-blue-500 text-blue-400' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Register Demo Analyst
          </button>
        </div>

        <form onSubmit={handleSubmit} className="mt-4 space-y-3">
          {mode === 'register' && (
            <div>
              <label className="block text-xs font-medium text-slate-300">Display Name</label>
              <input
                type="text"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                placeholder="Alex Rivera"
                className="mt-1 w-full border border-slate-700 bg-[#111827] px-3 py-2 text-sm text-slate-100 focus:border-blue-500 focus:outline-none"
              />
            </div>
          )}

          <div>
            <label className="block text-xs font-medium text-slate-300">Username</label>
            <input
              type="text"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="mt-1 w-full border border-slate-700 bg-[#111827] px-3 py-2 font-mono text-sm text-slate-100 focus:border-blue-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300">Password</label>
            <input
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="mt-1 w-full border border-slate-700 bg-[#111827] px-3 py-2 font-mono text-sm text-slate-100 focus:border-blue-500 focus:outline-none"
            />
          </div>

          {error && <p className="text-xs text-red-400">{error}</p>}

          <div className="border-t border-slate-800 pt-3 text-[11px] text-slate-400">
            <div className="flex items-center gap-1.5">
              <Lock className="h-3.5 w-3.5 text-slate-500" />
              <span>Analyst role triages alerts &amp; forensics. Administrator role tunes thresholds, retrains ML, &amp; resets data.</span>
            </div>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="border border-slate-700 px-4 py-2 text-xs font-medium text-slate-300 hover:bg-slate-800"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="bg-blue-600 px-4 py-2 text-xs font-medium text-white hover:bg-blue-500 disabled:opacity-50"
            >
              {loading ? 'Verifying...' : mode === 'login' ? 'Sign In' : 'Create Demo Analyst'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
