import { useState, useEffect, useCallback } from 'react';
import { Bug, AlertTriangle, ShieldCheck, Heart, RefreshCw, BarChart, Search } from 'lucide-react';
import { vulnsAPI } from '../api/client';
import toast from 'react-hot-toast';

export default function VulnerabilitiesPage() {
  const [vulns, setVulns] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = { page, page_size: 50 };
      if (search) params.search = search;
      if (severity) params.severity = severity;
      
      const res = await vulnsAPI.list(params);
      setVulns(res.data.items || []);
      setTotal(res.data.total || 0);

      const statsRes = await vulnsAPI.stats();
      setStats(statsRes.data);
    } catch {
      toast.error('Failed to load vulnerabilities');
    } finally {
      setLoading(false);
    }
  }, [page, search, severity]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 800 }}>Vulnerability Management</h1>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 2 }}>
            Track, prioritize, and remediate security vulnerabilities
          </p>
        </div>
        <button onClick={load} className="btn btn-ghost btn-sm">
          <RefreshCw size={14} />
        </button>
      </div>

      {/* Stats row */}
      {stats && (
        <div className="stats-grid" style={{ marginBottom: 20 }}>
          <div className="stat-card cyan">
            <div className="stat-label">Total Vulnerabilities</div>
            <div className="stat-value">{stats.total}</div>
          </div>
          <div className="stat-card critical">
            <div className="stat-label">Open Issues</div>
            <div className="stat-value">{stats.open}</div>
          </div>
          <div className="stat-card info">
            <div className="stat-label">Avg CVSS Score</div>
            <div className="stat-value">{stats.avg_cvss_score}</div>
          </div>
        </div>
      )}

      {/* Filter Row */}
      <div className="filters-row mb-4">
        <div className="search-bar" style={{ flex: 1 }}>
          <Search size={14} className="search-icon" />
          <input className="input" placeholder="Search CVE, Title, Software..." value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1); }} />
        </div>
        <select className="input" style={{ width: 180 }} value={severity}
          onChange={(e) => { setSeverity(e.target.value); setPage(1); }}>
          <option value="">All Severities</option>
          {['critical','high','medium','low'].map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>

      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
        {/* Main List */}
        <div style={{ flex: 2, minWidth: 320 }}>
          <div className="table-wrapper">
            {loading ? (
              <div className="page-loader"><div className="spinner" /></div>
            ) : vulns.length === 0 ? (
              <div className="empty-state"><Bug size={40} /><p>No vulnerabilities found</p></div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>CVE ID</th>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>CVSS</th>
                    <th>Software</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {vulns.map((v) => (
                    <tr key={v.id}>
                      <td className="font-mono" style={{ color: 'var(--accent-cyan)', fontWeight: 700 }}>
                        {v.cve_id || '—'}
                      </td>
                      <td style={{ color: 'var(--text-primary)', fontWeight: 500 }}>
                        <div>{v.title}</div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{v.description}</div>
                      </td>
                      <td><span className={`badge ${v.severity}`}>{v.severity}</span></td>
                      <td style={{ fontWeight: 700, fontSize: 13 }}>{v.cvss_score?.toFixed(1) || '0.0'}</td>
                      <td>{v.affected_software || '—'}</td>
                      <td>
                        <span className={`badge ${v.status === 'open' ? 'critical' : 'resolved'}`}>{v.status}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Critical CVEs list */}
        {stats?.critical_cves?.length > 0 && (
          <div style={{ width: 320 }}>
            <div className="card">
              <div className="card-header">
                <span className="card-title">🚨 Top CVSS Threats</span>
              </div>
              <div className="card-body" style={{ padding: '12px 16px' }}>
                {stats.critical_cves.map((c) => (
                  <div key={c.cve_id} style={{ padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                      <span className="font-mono" style={{ color: 'var(--critical)', fontWeight: 700 }}>{c.cve_id}</span>
                      <span style={{ fontWeight: 800, color: 'var(--critical)' }}>{c.cvss_score?.toFixed(1)}</span>
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text-secondary)' }} className="truncate">
                      {c.title}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
