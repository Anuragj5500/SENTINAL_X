import { useState, useEffect, useCallback } from 'react';
import { Plus, Monitor, Search } from 'lucide-react';
import { assetsAPI } from '../api/client';
import toast from 'react-hot-toast';

const CRIT_COLORS = { critical:'var(--critical)', high:'var(--high)', medium:'var(--medium)', low:'var(--low)' };

export default function AssetsPage() {
  const [assets, setAssets] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [criticality, setCriticality] = useState('');
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = { page, page_size: 50 };
      if (search) params.search = search;
      if (criticality) params.criticality = criticality;
      const res = await assetsAPI.list(params);
      setAssets(res.data.items || []);
      setTotal(res.data.total || 0);
    } catch { toast.error('Failed to load assets'); }
    finally { setLoading(false); }
  }, [page, search, criticality]);

  useEffect(() => { load(); }, [load]);

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 800 }}>Asset Inventory</h1>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 2 }}>{total} monitored assets</p>
        </div>
      </div>

      <div className="filters-row mb-4">
        <div className="search-bar" style={{ flex: 1 }}>
          <Search size={14} className="search-icon" />
          <input className="input" placeholder="Search hostname, IP…" value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1); }} />
        </div>
        <select className="input" style={{ width: 160 }} value={criticality}
          onChange={(e) => { setCriticality(e.target.value); setPage(1); }}>
          <option value="">All Criticality</option>
          {['critical','high','medium','low'].map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
      </div>

      {/* Asset Cards Grid */}
      {loading ? (
        <div className="page-loader"><div className="spinner" /></div>
      ) : assets.length === 0 ? (
        <div className="empty-state"><Monitor size={40} /><p>No assets found</p></div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 14 }}>
          {assets.map((a) => (
            <div key={a.id} className="card" style={{ transition: 'all 200ms' }}
              onMouseEnter={(e) => e.currentTarget.style.transform = 'translateY(-2px)'}
              onMouseLeave={(e) => e.currentTarget.style.transform = 'translateY(0)'}>
              <div style={{ padding: '14px 16px', borderBottom: '1px solid var(--border)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div>
                    <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 2 }}>{a.hostname}</div>
                    <div className="font-mono" style={{ fontSize: 12, color: 'var(--accent-cyan)' }}>{a.ip_address}</div>
                  </div>
                  <span className={`badge ${a.criticality}`}>{a.criticality}</span>
                </div>
              </div>
              <div style={{ padding: '12px 16px', display: 'flex', flexDirection: 'column', gap: 6 }}>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-muted">OS</span>
                  <span style={{ fontSize: 12 }}>{a.os_type || '—'}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-muted">Department</span>
                  <span style={{ fontSize: 12 }}>{a.department || '—'}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-muted">AV Status</span>
                  <span style={{
                    fontSize: 11, padding: '1px 6px', borderRadius: 4,
                    background: a.antivirus_status === 'active' ? 'rgba(16,185,129,0.15)' : 'rgba(255,59,92,0.15)',
                    color: a.antivirus_status === 'active' ? 'var(--success)' : 'var(--critical)'
                  }}>{a.antivirus_status}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-muted">Risk Score</span>
                  <span style={{
                    fontWeight: 700, fontSize: 13,
                    color: a.risk_score >= 75 ? 'var(--critical)' : a.risk_score >= 50 ? 'var(--high)' : 'var(--low)'
                  }}>{a.risk_score?.toFixed(0)}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-muted">Agent</span>
                  <span style={{ fontSize: 11, color: a.agent_installed ? 'var(--success)' : 'var(--text-muted)' }}>
                    {a.agent_installed ? '✓ Installed' : 'Not installed'}
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
