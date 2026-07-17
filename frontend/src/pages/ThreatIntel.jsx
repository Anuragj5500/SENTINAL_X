import { useState, useEffect } from 'react';
import { Globe, Search, ShieldAlert, Cpu, Heart, CheckCircle } from 'lucide-react';
import { threatIntelAPI } from '../api/client';
import toast from 'react-hot-toast';

export default function ThreatIntelPage() {
  const [feeds, setFeeds] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [enrichQuery, setEnrichQuery] = useState('');
  const [enrichType, setEnrichType] = useState('ip');
  const [enrichResult, setEnrichResult] = useState(null);
  const [enrichLoading, setEnrichLoading] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const feedRes = await threatIntelAPI.listFeeds();
      setFeeds(feedRes.data);

      const statsRes = await threatIntelAPI.feedStats();
      setStats(statsRes.data);
    } catch {
      toast.error('Failed to load Threat Intel feeds');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const handleEnrich = async (e) => {
    e.preventDefault();
    if (!enrichQuery.trim()) return;
    setEnrichLoading(true);
    setEnrichResult(null);
    try {
      let res;
      if (enrichType === 'ip') res = await threatIntelAPI.enrichIP(enrichQuery);
      else if (enrichType === 'hash') res = await threatIntelAPI.enrichHash(enrichQuery);
      else res = await threatIntelAPI.enrichDomain(enrichQuery);

      setEnrichResult(res.data);
      toast.success('Enrichment complete!');
      load(); // Reload feeds to pick up newly added IOCs
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Enrichment failed');
    } finally {
      setEnrichLoading(false);
    }
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 800 }}>Threat Intelligence</h1>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 2 }}>
            IOC feeds, IP reputation checks, and malware hash enrichment
          </p>
        </div>
      </div>

      {/* Enrichment Section */}
      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', marginBottom: 20 }}>
        <div style={{ flex: 1, minWidth: 320 }}>
          <div className="card">
            <div className="card-header"><span className="card-title">🔍 Quick IOC Enrichment</span></div>
            <div className="card-body">
              <form onSubmit={handleEnrich} style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
                <select className="input" style={{ width: 100 }} value={enrichType}
                  onChange={(e) => setEnrichType(e.target.value)}>
                  <option value="ip">IP</option>
                  <option value="domain">Domain</option>
                  <option value="hash">Hash</option>
                </select>
                <input
                  className="input"
                  placeholder={enrichType === 'ip' ? '8.8.8.8' : enrichType === 'domain' ? 'evil.com' : 'MD5/SHA256 hash...'}
                  value={enrichQuery}
                  onChange={(e) => setEnrichQuery(e.target.value)}
                  style={{ flex: 1 }}
                  required
                />
                <button type="submit" className="btn btn-primary" disabled={enrichLoading}>
                  {enrichLoading ? <div className="spinner" style={{ width: 14, height: 14 }} /> : 'Enrich'}
                </button>
              </form>

              {enrichResult && (
                <div style={{
                  background: 'var(--bg-base)', border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-sm)', padding: 12, fontSize: 13
                }}>
                  <h4 style={{ fontWeight: 700, marginBottom: 8, color: 'var(--accent-cyan)' }}>Enrichment Results:</h4>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    <div className="flex justify-between">
                      <span className="text-muted">Is Malicious:</span>
                      <span style={{ fontWeight: 700, color: enrichResult.is_malicious ? 'var(--critical)' : 'var(--success)' }}>
                        {enrichResult.is_malicious ? 'YES' : 'NO'}
                      </span>
                    </div>
                    {enrichResult.risk_score !== undefined && (
                      <div className="flex justify-between">
                        <span className="text-muted">Risk Score:</span>
                        <span style={{ fontWeight: 700 }}>{enrichResult.risk_score}%</span>
                      </div>
                    )}
                    {enrichResult.threat_type && (
                      <div className="flex justify-between">
                        <span className="text-muted">Threat Type:</span>
                        <span>{enrichResult.threat_type}</span>
                      </div>
                    )}
                    {enrichResult.details && (
                      <div style={{ borderTop: '1px solid var(--border)', paddingTop: 6, marginTop: 4 }}>
                        <span className="text-muted" style={{ display: 'block', marginBottom: 4 }}>Details:</span>
                        <pre style={{
                          fontFamily: 'JetBrains Mono', fontSize: 11, background: 'var(--bg-hover)',
                          padding: 6, borderRadius: 4, overflowX: 'auto'
                        }}>{JSON.stringify(enrichResult.details, null, 2)}</pre>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Stats */}
        {stats && (
          <div style={{ width: 300 }}>
            <div className="card" style={{ height: '100%' }}>
              <div className="card-header"><span className="card-title">📊 Threat Feed Stats</span></div>
              <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div className="flex justify-between items-center">
                  <span className="text-muted">Total Seeded IOCs:</span>
                  <span style={{ fontSize: 18, fontWeight: 800 }}>{stats.total_iocs}</span>
                </div>
                <div style={{ borderTop: '1px solid var(--border)', paddingTop: 10 }}>
                  <div className="text-xs text-muted" style={{ marginBottom: 6 }}>IOC Breakdown</div>
                  {Object.entries(stats.by_type || {}).map(([type, count]) => (
                    <div key={type} className="flex justify-between" style={{ padding: '4px 0', fontSize: 13 }}>
                      <span style={{ textTransform: 'uppercase', fontWeight: 600 }}>{type}s</span>
                      <span className="font-mono">{count}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Feeds Table */}
      <div className="card">
        <div className="card-header"><span className="card-title"><Globe size={14} /> Active Intel Feed</span></div>
        <div className="table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
          {loading ? (
            <div className="page-loader"><div className="spinner" /></div>
          ) : feeds.length === 0 ? (
            <div className="empty-state"><Globe size={40} /><p>No threat intelligence feeds configured</p></div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Value</th>
                  <th>Type</th>
                  <th>Threat Type</th>
                  <th>Confidence</th>
                  <th>Source</th>
                  <th>Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {feeds.map((f) => (
                  <tr key={f.id}>
                    <td className="font-mono" style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{f.ioc_value}</td>
                    <td><span className="badge info">{f.ioc_type}</span></td>
                    <td>{f.threat_type}</td>
                    <td>
                      <span style={{
                        fontWeight: 700,
                        color: f.confidence >= 90 ? 'var(--critical)' : f.confidence >= 75 ? 'var(--high)' : 'var(--medium)'
                      }}>{f.confidence}%</span>
                    </td>
                    <td>{f.source}</td>
                    <td className="text-xs text-muted">{new Date(f.last_seen).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
