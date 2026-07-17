import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Plus, Search, RefreshCw, Folder } from 'lucide-react';
import { incidentsAPI } from '../api/client';
import { formatDistanceToNow } from 'date-fns';
import toast from 'react-hot-toast';

const STATUS_ORDER = ['open','assigned','investigating','containment','recovery','resolved','closed'];

export default function IncidentsPage() {
  const navigate = useNavigate();
  const [incidents, setIncidents] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState({ status: '', search: '' });
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [newInc, setNewInc] = useState({ title: '', severity: 'high', description: '' });

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = { page, page_size: 50, ...Object.fromEntries(Object.entries(filters).filter(([, v]) => v)) };
      const res = await incidentsAPI.list(params);
      setIncidents(res.data.items || []);
      setTotal(res.data.total || 0);
    } catch { toast.error('Failed to load incidents'); }
    finally { setLoading(false); }
  }, [page, filters]);

  useEffect(() => { load(); }, [load]);

  const handleCreate = async (e) => {
    e.preventDefault();
    try {
      await incidentsAPI.create(newInc);
      toast.success('Incident created');
      setCreating(false);
      setNewInc({ title: '', severity: 'high', description: '' });
      load();
    } catch { toast.error('Failed to create'); }
  };

  const setFilter = (k, v) => { setFilters((f) => ({ ...f, [k]: v })); setPage(1); };

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 800 }}>Incidents</h1>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 2 }}>{total} incidents</p>
        </div>
        <div className="flex gap-2">
          <button onClick={load} className="btn btn-ghost btn-sm"><RefreshCw size={14} /></button>
          <button onClick={() => setCreating(true)} className="btn btn-primary btn-sm">
            <Plus size={14} /> New Incident
          </button>
        </div>
      </div>

      {/* Create Modal */}
      {creating && (
        <div style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000
        }}>
          <div className="card" style={{ width: 480 }}>
            <div className="card-header">
              <span className="card-title">Create Incident</span>
              <button className="btn btn-ghost btn-sm" onClick={() => setCreating(false)}>✕</button>
            </div>
            <form onSubmit={handleCreate}>
              <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                <div className="input-group">
                  <label className="input-label">Title</label>
                  <input className="input" required value={newInc.title}
                    onChange={(e) => setNewInc({ ...newInc, title: e.target.value })}
                    placeholder="Incident title" />
                </div>
                <div className="input-group">
                  <label className="input-label">Severity</label>
                  <select className="input" value={newInc.severity}
                    onChange={(e) => setNewInc({ ...newInc, severity: e.target.value })}>
                    {['critical','high','medium','low'].map((s) => <option key={s} value={s}>{s}</option>)}
                  </select>
                </div>
                <div className="input-group">
                  <label className="input-label">Description</label>
                  <textarea className="input" rows={3} value={newInc.description}
                    onChange={(e) => setNewInc({ ...newInc, description: e.target.value })}
                    placeholder="Describe the incident…" />
                </div>
                <div className="flex gap-2" style={{ justifyContent: 'flex-end' }}>
                  <button type="button" className="btn btn-ghost" onClick={() => setCreating(false)}>Cancel</button>
                  <button type="submit" className="btn btn-primary">Create</button>
                </div>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="filters-row mb-4">
        <div className="search-bar" style={{ flex: 1 }}>
          <Search size={14} className="search-icon" />
          <input className="input" placeholder="Search incidents…" value={filters.search}
            onChange={(e) => setFilter('search', e.target.value)} />
        </div>
        <select className="input" style={{ width: 180 }} value={filters.status}
          onChange={(e) => setFilter('status', e.target.value)}>
          <option value="">All Statuses</option>
          {STATUS_ORDER.map((s) => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
        </select>
      </div>

      {/* Table */}
      <div className="table-wrapper">
        {loading ? (
          <div className="page-loader"><div className="spinner" /></div>
        ) : incidents.length === 0 ? (
          <div className="empty-state"><Folder size={40} /><p>No incidents found</p></div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>P</th>
                <th>Title</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Tags</th>
                <th>MITRE</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {incidents.map((inc) => (
                <tr key={inc.id} onClick={() => navigate(`/incidents/${inc.id}`)} style={{ cursor: 'pointer' }}>
                  <td>
                    <span style={{
                      display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                      width: 22, height: 22, borderRadius: 4, fontSize: 11, fontWeight: 800,
                      background: ['','rgba(255,59,92,0.2)','rgba(255,140,66,0.2)','rgba(245,200,66,0.2)','rgba(66,212,160,0.2)'][inc.priority] || 'var(--border)',
                      color: ['','var(--critical)','var(--high)','var(--medium)','var(--low)'][inc.priority] || 'var(--text-muted)',
                    }}>P{inc.priority}</span>
                  </td>
                  <td style={{ maxWidth: 220, color: 'var(--text-primary)', fontWeight: 500 }}
                      className="truncate">{inc.title}</td>
                  <td><span className={`badge ${inc.severity}`}>{inc.severity}</span></td>
                  <td><span className={`badge ${inc.status}`}>{inc.status.replace('_',' ')}</span></td>
                  <td>
                    {(inc.tags || []).slice(0, 2).map((t) => (
                      <span key={t} style={{
                        fontSize: 10, padding: '2px 6px', borderRadius: 4, marginRight: 4,
                        background: 'var(--bg-hover)', color: 'var(--text-muted)'
                      }}>{t}</span>
                    ))}
                  </td>
                  <td className="font-mono" style={{ color: 'var(--accent-cyan)', fontSize: 11 }}>
                    {(inc.mitre_techniques || []).slice(0, 2).join(', ') || '—'}
                  </td>
                  <td className="text-xs text-muted">
                    {inc.created_at ? formatDistanceToNow(new Date(inc.created_at), { addSuffix: true }) : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
