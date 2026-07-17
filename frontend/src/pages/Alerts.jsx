import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Filter, RefreshCw, AlertTriangle } from 'lucide-react';
import { alertsAPI } from '../api/client';
import toast from 'react-hot-toast';
import { formatDistanceToNow } from 'date-fns';

export default function AlertsPage() {
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({ severity: '', status: '', search: '', hostname: '' });

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = { page, page_size: 50, ...Object.fromEntries(Object.entries(filters).filter(([, v]) => v)) };
      const res = await alertsAPI.list(params);
      setAlerts(res.data.items || []);
      setTotal(res.data.total || 0);
    } catch { toast.error('Failed to load alerts'); }
    finally { setLoading(false); }
  }, [page, filters]);

  useEffect(() => { load(); }, [load]);

  const handleAcknowledge = async (id, e) => {
    e.stopPropagation();
    try {
      await alertsAPI.acknowledge(id);
      toast.success('Alert acknowledged');
      load();
    } catch { toast.error('Failed'); }
  };

  const setFilter = (key, val) => { setFilters((f) => ({ ...f, [key]: val })); setPage(1); };

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 800 }}>Alerts</h1>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 2 }}>
            {total.toLocaleString()} total alerts
          </p>
        </div>
        <button onClick={load} className="btn btn-ghost btn-sm">
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-body" style={{ padding: '14px 20px' }}>
          <div className="filters-row">
            <div className="search-bar" style={{ flex: 1, minWidth: 200 }}>
              <Search size={14} className="search-icon" />
              <input
                className="input"
                placeholder="Search alerts…"
                value={filters.search}
                onChange={(e) => setFilter('search', e.target.value)}
              />
            </div>
            <select className="input" style={{ width: 140 }} value={filters.severity}
              onChange={(e) => setFilter('severity', e.target.value)}>
              <option value="">All Severities</option>
              {['critical','high','medium','low','info'].map((s) => (
                <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
              ))}
            </select>
            <select className="input" style={{ width: 160 }} value={filters.status}
              onChange={(e) => setFilter('status', e.target.value)}>
              <option value="">All Statuses</option>
              {['open','acknowledged','investigating','false_positive','resolved'].map((s) => (
                <option key={s} value={s}>{s.replace('_', ' ')}</option>
              ))}
            </select>
            <input
              className="input"
              style={{ width: 160 }}
              placeholder="Hostname…"
              value={filters.hostname}
              onChange={(e) => setFilter('hostname', e.target.value)}
            />
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="table-wrapper">
        {loading ? (
          <div className="page-loader"><div className="spinner" /></div>
        ) : alerts.length === 0 ? (
          <div className="empty-state">
            <AlertTriangle size={40} />
            <p>No alerts found</p>
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Title</th>
                <th>Hostname</th>
                <th>Source IP</th>
                <th>MITRE</th>
                <th>Status</th>
                <th>Risk</th>
                <th>Time</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((a) => (
                <tr key={a.id} onClick={() => navigate(`/alerts/${a.id}`)}
                  style={{ cursor: 'pointer' }}>
                  <td><span className={`badge ${a.severity}`}>{a.severity}</span></td>
                  <td style={{ maxWidth: 220, color: 'var(--text-primary)', fontWeight: 500 }}
                      className="truncate">{a.title}</td>
                  <td className="font-mono">{a.hostname || '—'}</td>
                  <td className="font-mono">{a.source_ip || '—'}</td>
                  <td className="font-mono" style={{ color: 'var(--accent-cyan)' }}>
                    {a.mitre_technique || '—'}
                  </td>
                  <td><span className={`badge ${a.status}`}>{a.status.replace('_',' ')}</span></td>
                  <td>
                    <span style={{
                      fontWeight: 700, fontSize: 12,
                      color: a.risk_score >= 80 ? 'var(--critical)' : a.risk_score >= 60 ? 'var(--high)' : 'var(--medium)'
                    }}>{a.risk_score?.toFixed(0)}</span>
                  </td>
                  <td className="text-xs text-muted">
                    {a.created_at ? formatDistanceToNow(new Date(a.created_at), { addSuffix: true }) : '—'}
                  </td>
                  <td>
                    {a.status === 'open' && (
                      <button
                        className="btn btn-ghost btn-sm"
                        onClick={(e) => handleAcknowledge(a.id, e)}
                      >Ack</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Pagination */}
      {total > 50 && (
        <div className="flex items-center justify-between" style={{ marginTop: 16 }}>
          <span className="text-sm text-muted">
            Showing {Math.min((page - 1) * 50 + 1, total)}–{Math.min(page * 50, total)} of {total}
          </span>
          <div className="flex gap-2">
            <button className="btn btn-ghost btn-sm" onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}>
              ← Prev
            </button>
            <button className="btn btn-ghost btn-sm" onClick={() => setPage(p => p + 1)} disabled={page * 50 >= total}>
              Next →
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
