import { useState } from 'react';
import { Search, Bookmark, ChevronRight, HelpCircle, Sparkles, Filter } from 'lucide-react';
import { huntAPI } from '../api/client';
import { formatDistanceToNow } from 'date-fns';
import toast from 'react-hot-toast';

export default function HuntPage() {
  const [query, setQuery] = useState({
    q: '',
    process_name: '',
    hostname: '',
    source_ip: '',
    user: '',
    command: '',
    hash_value: ''
  });
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [saved, setSaved] = useState([]);
  const [savedLoaded, setSavedLoaded] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);

  const loadSaved = async () => {
    if (savedLoaded) return;
    try {
      const res = await huntAPI.savedSearches();
      setSaved(res.data);
      setSavedLoaded(true);
    } catch {
      toast.error('Failed to load saved searches');
    }
  };

  const handleSearch = async (e) => {
    e?.preventDefault();
    setLoading(true);
    try {
      const params = Object.fromEntries(
        Object.entries(query).filter(([, v]) => v)
      );
      const res = await huntAPI.search(params);
      setResults(res.data);
    } catch {
      toast.error('Search failed');
    } finally {
      setLoading(false);
    }
  };

  const applyQueryTemplate = (qStr) => {
    setQuery((prev) => ({ ...prev, q: qStr }));
  };

  const applySaved = (search) => {
    setQuery((q) => ({ ...q, ...search.params }));
  };

  const queryTemplates = [
    {
      label: 'Mimikatz Run',
      q: 'process_name:mimikatz.exe OR command:mimikatz',
      desc: 'Detect credentials dumping process runs'
    },
    {
      label: 'Admin PowerShell',
      q: 'process_name:powershell.exe AND user:admin',
      desc: 'Identify PowerShell scripts executed under admin contexts'
    },
    {
      label: 'Brute Force Auth Failures',
      q: 'event_type:authentication_failure AND NOT user:SYSTEM',
      desc: 'Filter brute force attempts omitting system processes'
    },
    {
      label: 'Remote Windows Share access',
      q: 'event_id:5140 AND NOT source_ip:127.0.0.1',
      desc: 'Find remote share connections not origin local'
    }
  ];

  return (
    <div className="threat-hunt-container">
      {/* Page Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 800 }}>Threat Hunting</h1>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 2 }}>
            Query security telemetry logs and alerts using advanced KQL/SPL boolean filters.
          </p>
        </div>
        <button className="btn btn-ghost btn-sm" onClick={loadSaved}>
          <Bookmark size={14} /> Saved Searches
        </button>
      </div>

      {/* Saved Searches */}
      {saved.length > 0 && (
        <div className="card mb-4">
          <div className="card-header"><span className="card-title">📌 Saved Searches</span></div>
          <div className="card-body" style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
            {saved.map((s) => (
              <button key={s.name} className="btn btn-ghost btn-sm" onClick={() => applySaved(s)}>
                {s.name} <ChevronRight size={12} />
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Primary Search Bar */}
      <div className="card mb-4">
        <div className="card-header flex justify-between" style={{ alignItems: 'center' }}>
          <span className="card-title"><Search size={14} /> KQL Hunt Query</span>
          <button 
            type="button" 
            className={`btn btn-sm ${showAdvanced ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => setShowAdvanced(!showAdvanced)}
            style={{ fontSize: 11, padding: '4px 10px', height: 'auto' }}
          >
            <Filter size={11} /> {showAdvanced ? 'Hide Fields' : 'Field Filters'}
          </button>
        </div>
        <form onSubmit={handleSearch}>
          <div className="card-body">
            {/* Search Input Box */}
            <div className="search-bar-primary mb-3">
              <input
                id="hunt-query"
                name="hunt-query"
                className="input primary-hunt-input"
                placeholder='Enter hunt query, e.g. event_type:process_creation AND command:"mimikatz" AND NOT user:SYSTEM'
                value={query.q}
                onChange={(e) => setQuery((prev) => ({ ...prev, q: e.target.value }))}
                style={{ fontSize: 14, padding: '14px 16px', background: 'var(--bg-input)' }}
              />
              <button type="submit" className="btn btn-primary primary-search-btn" disabled={loading}>
                {loading ? <div className="spinner" style={{ width: 14, height: 14 }} /> : <Search size={16} />}
                Hunt
              </button>
            </div>

            {/* Quick Templates */}
            <div className="query-templates-row mb-3">
              <span className="template-label"><Sparkles size={11} /> Quick Templates:</span>
              <div className="templates-badges-list">
                {queryTemplates.map((t, idx) => (
                  <button
                    key={idx}
                    type="button"
                    className="template-badge"
                    onClick={() => applyQueryTemplate(t.q)}
                    title={t.desc}
                  >
                    {t.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Syntax Help Alert Box */}
            <div className="tip-alert-box mb-3 text-xs">
              <strong>Query Grammar:</strong> Combine conditions using <code>AND</code> and <code>NOT</code>. 
              Use syntax like <code>key:value</code>. Valid fields include: <code>event_type</code>, <code>command</code>, <code>user</code>, <code>process_name</code>, <code>hostname</code>, <code>source_ip</code>, and <code>severity</code>.
            </div>

            {/* Legacy Advanced Fields Grid (collapsible) */}
            {showAdvanced && (
              <div className="advanced-fields-box">
                <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--accent-cyan)', marginBottom: 8, textTransform: 'uppercase' }}>
                  Field-Specific Overrides
                </div>
                <div className="grid-3" style={{ gap: 12 }}>
                  {[
                    ['process_name', 'Process Name'],
                    ['hostname', 'Hostname'],
                    ['source_ip', 'Source IP'],
                    ['user', 'Username'],
                    ['command', 'Command Contains'],
                    ['hash_value', 'File Hash'],
                  ].map(([key, label]) => (
                    <div key={key} className="input-group">
                      <label className="input-label" style={{ fontSize: 10 }}>{label}</label>
                      <input
                        id={`field-${key}`}
                        name={key}
                        className="input"
                        placeholder={label}
                        value={query[key]}
                        style={{ padding: '6px 10px', fontSize: 12 }}
                        onChange={(e) => setQuery((q) => ({ ...q, [key]: e.target.value }))}
                      />
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="flex gap-2 mt-3 justify-end">
              <button 
                type="button" 
                className="btn btn-ghost btn-sm"
                onClick={() => setQuery({ q:'', process_name:'', hostname:'', source_ip:'', user:'', command:'', hash_value:'' })}
              >
                Reset Query
              </button>
            </div>
          </div>
        </form>
      </div>

      {/* Results */}
      {results && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Alerts hits */}
          {results.alerts?.length > 0 && (
            <div className="card">
              <div className="card-header">
                <span className="card-title">🚨 Alert Matches ({results.alerts.length})</span>
              </div>
              <div className="table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
                <table>
                  <thead><tr><th>Title</th><th>Severity</th><th>Hostname</th><th>MITRE</th><th>Time</th></tr></thead>
                  <tbody>
                    {results.alerts.map((a) => (
                      <tr key={a.id}>
                        <td style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{a.title}</td>
                        <td><span className={`badge ${a.severity}`}>{a.severity}</span></td>
                        <td className="font-mono">{a.hostname || '—'}</td>
                        <td className="font-mono" style={{ color: 'var(--accent-cyan)' }}>{a.mitre_technique || '—'}</td>
                        <td className="text-xs text-muted">{a.created_at ? formatDistanceToNow(new Date(a.created_at), { addSuffix: true }) : '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Log hits */}
          {results.logs?.length > 0 && (
            <div className="card">
              <div className="card-header">
                <span className="card-title">📋 Log Matches ({results.log_count?.toLocaleString() || results.logs.length})</span>
              </div>
              <div className="table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
                <table>
                  <thead><tr><th>Time</th><th>Hostname</th><th>User</th><th>Event</th><th>Process</th><th>Severity</th></tr></thead>
                  <tbody>
                    {results.logs.map((l) => (
                      <tr key={l.id}>
                        <td className="text-xs text-muted">{l.timestamp ? new Date(l.timestamp).toLocaleString() : '—'}</td>
                        <td className="font-mono">{l.hostname || '—'}</td>
                        <td>{l.user || '—'}</td>
                        <td style={{ color: 'var(--text-primary)' }}>{l.event_type}</td>
                        <td className="font-mono">{l.process_name || '—'}</td>
                        <td><span className={`badge ${l.severity}`}>{l.severity}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {results.logs?.length === 0 && results.alerts?.length === 0 && (
            <div className="empty-state"><Search size={40} /><p>No results found matching query</p></div>
          )}
        </div>
      )}

      {/* Styled KQL elements */}
      <style>{`
        .search-bar-primary {
          display: flex;
          gap: 10px;
          position: relative;
        }
        .primary-hunt-input {
          flex: 1;
          border-radius: var(--radius-md) !important;
          border: 1px solid var(--border) !important;
        }
        .primary-hunt-input:focus {
          border-color: var(--accent-cyan) !important;
          box-shadow: var(--glow-cyan) !important;
        }
        .primary-search-btn {
          border-radius: var(--radius-md);
          font-weight: 700;
          padding: 0 24px;
        }
        .query-templates-row {
          display: flex;
          align-items: center;
          gap: 12px;
          flex-wrap: wrap;
        }
        .template-label {
          font-size: 11px;
          font-weight: 700;
          color: var(--text-secondary);
          display: inline-flex;
          align-items: center;
          gap: 4px;
        }
        .templates-badges-list {
          display: flex;
          gap: 8px;
          flex-wrap: wrap;
        }
        .template-badge {
          background: var(--bg-hover);
          border: 1px solid var(--border);
          color: var(--text-secondary);
          padding: 4px 10px;
          border-radius: 20px;
          font-size: 11px;
          font-weight: 600;
          cursor: pointer;
          transition: all var(--transition);
        }
        .template-badge:hover {
          color: var(--accent-cyan);
          border-color: var(--accent-cyan);
          background: rgba(0, 212, 255, 0.05);
        }
        .advanced-fields-box {
          background: var(--bg-surface);
          border: 1px solid var(--border);
          border-radius: var(--radius-md);
          padding: 16px;
          margin-top: 12px;
          animation: slideDown 200ms ease-out;
        }
        @keyframes slideDown {
          from { opacity: 0; transform: translateY(-4px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  );
}
