import { useState, useEffect, useCallback } from 'react';
import { Settings, User, ShieldAlert, Cpu, Heart, CheckCircle, RefreshCw } from 'lucide-react';
import { adminAPI } from '../api/client';
import toast from 'react-hot-toast';

export default function AdminPage() {
  const [users, setUsers] = useState([]);
  const [systemStats, setSystemStats] = useState(null);
  const [auditLogs, setAuditLogs] = useState([]);
  const [auditTotal, setAuditTotal] = useState(0);
  const [auditPage, setAuditPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('users');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      if (activeTab === 'users') {
        const usersRes = await adminAPI.listUsers();
        setUsers(usersRes.data);
      } else if (activeTab === 'stats') {
        const statsRes = await adminAPI.systemStats();
        setSystemStats(statsRes.data);
      } else {
        const logsRes = await adminAPI.auditLogs({ page: auditPage, page_size: 50 });
        setAuditLogs(logsRes.data.items || []);
        setAuditTotal(logsRes.data.total || 0);
      }
    } catch {
      toast.error('Failed to load admin module data');
    } finally {
      setLoading(false);
    }
  }, [activeTab, auditPage]);

  useEffect(() => {
    load();
  }, [load]);

  const handleToggleUser = async (id) => {
    try {
      const res = await adminAPI.toggleUser(id);
      toast.success(`User is now ${res.data.is_active ? 'active' : 'inactive'}`);
      load();
    } catch {
      toast.error('Failed to update user');
    }
  };

  const handleRoleChange = async (id, role) => {
    try {
      await adminAPI.updateRole(id, role);
      toast.success('Role updated successfully');
      load();
    } catch {
      toast.error('Failed to update role');
    }
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 800 }}>Admin Panel</h1>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 2 }}>
            Manage platform configuration, user roles, and inspect security audit logs
          </p>
        </div>
        <button onClick={load} className="btn btn-ghost btn-sm">
          <RefreshCw size={14} />
        </button>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 16, borderBottom: '1px solid var(--border)' }}>
        <button
          onClick={() => { setActiveTab('users'); setLoading(true); }}
          className="btn btn-ghost"
          style={{
            borderBottom: activeTab === 'users' ? '2px solid var(--accent-cyan)' : 'none',
            color: activeTab === 'users' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            borderRadius: 0,
            paddingBottom: 10,
          }}
        >
          User Management
        </button>
        <button
          onClick={() => { setActiveTab('stats'); setLoading(true); }}
          className="btn btn-ghost"
          style={{
            borderBottom: activeTab === 'stats' ? '2px solid var(--accent-cyan)' : 'none',
            color: activeTab === 'stats' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            borderRadius: 0,
            paddingBottom: 10,
          }}
        >
          System Health
        </button>
        <button
          onClick={() => { setActiveTab('audit'); setLoading(true); }}
          className="btn btn-ghost"
          style={{
            borderBottom: activeTab === 'audit' ? '2px solid var(--accent-cyan)' : 'none',
            color: activeTab === 'audit' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            borderRadius: 0,
            paddingBottom: 10,
          }}
        >
          Audit Logs
        </button>
      </div>

      {loading ? (
        <div className="page-loader"><div className="spinner" /></div>
      ) : activeTab === 'users' ? (
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Username</th>
                <th>Email</th>
                <th>Role</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id}>
                  <td style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{u.username}</td>
                  <td>{u.email}</td>
                  <td>
                    <select
                      className="input"
                      style={{ width: 160, padding: '4px 8px' }}
                      value={u.role}
                      onChange={(e) => handleRoleChange(u.id, e.target.value)}
                    >
                      {['super_admin','soc_manager','analyst','threat_hunter','responder','auditor','readonly'].map((r) => (
                        <option key={r} value={r}>{r.replace('_', ' ')}</option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <span className={`badge ${u.is_active ? 'resolved' : 'critical'}`}>
                      {u.is_active ? 'Active' : 'Locked'}
                    </span>
                  </td>
                  <td>
                    <button
                      className={`btn btn-sm ${u.is_active ? 'btn-danger' : 'btn-success'}`}
                      onClick={() => handleToggleUser(u.id)}
                    >
                      {u.is_active ? 'Disable' : 'Enable'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : activeTab === 'stats' ? (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 16 }}>
          <div className="card">
            <div className="card-header"><span className="card-title">💾 Database Allocation</span></div>
            <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div className="flex justify-between">
                <span className="text-muted">Total Users:</span>
                <span style={{ fontWeight: 700 }}>{systemStats?.total_users}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted">Registered Assets:</span>
                <span style={{ fontWeight: 700 }}>{systemStats?.total_assets}</span>
              </div>
            </div>
          </div>
          <div className="card">
            <div className="card-header"><span className="card-title">⚡ Detections Engine</span></div>
            <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div className="flex justify-between">
                <span className="text-muted">Total Rules:</span>
                <span style={{ fontWeight: 700 }}>{systemStats?.total_rules}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted">Active Rules:</span>
                <span style={{ fontWeight: 700, color: 'var(--success)' }}>{systemStats?.active_rules}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted">Total SOAR Playbooks:</span>
                <span style={{ fontWeight: 700 }}>{systemStats?.total_playbooks}</span>
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div>
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Action</th>
                  <th>IP Address</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {auditLogs.map((l) => (
                  <tr key={l.id}>
                    <td className="text-xs text-muted">{new Date(l.created_at).toLocaleString()}</td>
                    <td style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{l.action}</td>
                    <td className="font-mono">{l.ip_address || '—'}</td>
                    <td className="font-mono text-xs truncate" style={{ maxWidth: 300 }}>
                      {JSON.stringify(l.details)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {auditTotal > 50 && (
            <div className="flex items-center justify-between" style={{ marginTop: 16 }}>
              <span className="text-sm text-muted">
                Showing {Math.min((auditPage - 1) * 50 + 1, auditTotal)}–{Math.min(auditPage * 50, auditTotal)} of {auditTotal}
              </span>
              <div className="flex gap-2">
                <button className="btn btn-ghost btn-sm" onClick={() => setAuditPage(p => Math.max(1, p - 1))} disabled={auditPage === 1}>
                  ← Prev
                </button>
                <button className="btn btn-ghost btn-sm" onClick={() => setAuditPage(p => p + 1)} disabled={auditPage * 50 >= auditTotal}>
                  Next →
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
