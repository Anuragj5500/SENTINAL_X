import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Brain, Zap, Shield } from 'lucide-react';
import { alertsAPI } from '../api/client';
import toast from 'react-hot-toast';

export default function AlertDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [alert, setAlert] = useState(null);
  const [loading, setLoading] = useState(true);
  const [aiLoading, setAiLoading] = useState(false);

  useEffect(() => {
    alertsAPI.get(id).then((r) => setAlert(r.data)).catch(() => toast.error('Alert not found')).finally(() => setLoading(false));
  }, [id]);

  if (loading) return <div className="page-loader"><div className="spinner" style={{ width: 36, height: 36 }} /></div>;
  if (!alert) return <div className="empty-state"><p>Alert not found</p></div>;

  const fields = [
    { label: 'Hostname',        value: alert.hostname },
    { label: 'Source IP',       value: alert.source_ip, mono: true },
    { label: 'Destination IP',  value: alert.destination_ip, mono: true },
    { label: 'User',            value: alert.user },
    { label: 'Process',         value: alert.process_name, mono: true },
    { label: 'Log Source',      value: alert.source },
    { label: 'Risk Score',      value: alert.risk_score?.toFixed(1) },
    { label: 'Created',         value: alert.created_at ? new Date(alert.created_at).toLocaleString() : '—' },
  ];

  return (
    <div>
      <button className="btn btn-ghost btn-sm" onClick={() => navigate('/alerts')} style={{ marginBottom: 20 }}>
        <ArrowLeft size={14} /> Back to Alerts
      </button>

      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', marginBottom: 24 }}>
        <div style={{ flex: 2, minWidth: 300 }}>
          <div className="card">
            <div className="card-header">
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                  <span className={`badge ${alert.severity}`}>{alert.severity}</span>
                  <span className={`badge ${alert.status}`}>{alert.status.replace('_',' ')}</span>
                </div>
                <h2 style={{ fontSize: 18, fontWeight: 700 }}>{alert.title}</h2>
              </div>
            </div>
            <div className="card-body">
              <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 20 }}>{alert.description}</p>

              <div className="grid-2" style={{ gap: 12 }}>
                {fields.map((f) => f.value && (
                  <div key={f.label}>
                    <div className="text-xs text-muted" style={{ marginBottom: 2 }}>{f.label}</div>
                    <div className={f.mono ? 'font-mono' : ''} style={{ fontSize: 13, color: 'var(--text-primary)' }}>
                      {f.value}
                    </div>
                  </div>
                ))}
              </div>

              {alert.command && (
                <div style={{ marginTop: 16 }}>
                  <div className="text-xs text-muted" style={{ marginBottom: 4 }}>Command</div>
                  <div style={{
                    background: 'var(--bg-base)', borderRadius: 6, padding: '10px 12px',
                    fontFamily: 'JetBrains Mono', fontSize: 12, color: 'var(--accent-cyan)',
                    border: '1px solid var(--border)', overflowX: 'auto', wordBreak: 'break-all'
                  }}>{alert.command}</div>
                </div>
              )}
            </div>
          </div>
        </div>

        <div style={{ flex: 1, minWidth: 260, display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* MITRE */}
          {alert.mitre_technique && (
            <div className="card">
              <div className="card-header">
                <span className="card-title"><Shield size={14} /> MITRE ATT&amp;CK</span>
              </div>
              <div className="card-body">
                <div style={{ marginBottom: 8 }}>
                  <div className="text-xs text-muted">Tactic</div>
                  <div style={{ fontWeight: 600, color: 'var(--high)' }}>{alert.mitre_tactic || '—'}</div>
                </div>
                <div>
                  <div className="text-xs text-muted">Technique</div>
                  <div className="font-mono" style={{ color: 'var(--accent-cyan)', fontWeight: 700 }}>
                    {alert.mitre_technique}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Enrichment */}
          {Object.keys(alert.enrichment_data || {}).length > 0 && (
            <div className="card">
              <div className="card-header">
                <span className="card-title">🔍 Threat Intel</span>
              </div>
              <div className="card-body">
                {Object.entries(alert.enrichment_data).map(([k, v]) => (
                  <div key={k} style={{ marginBottom: 6 }}>
                    <div className="text-xs text-muted">{k}</div>
                    <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{String(v)}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* AI Analysis */}
      <div className="card">
        <div className="card-header">
          <span className="card-title"><Brain size={14} /> AI Security Analysis</span>
        </div>
        <div className="card-body">
          {alert.ai_analysis ? (
            <div style={{
              background: 'var(--bg-base)', borderRadius: 8, padding: '16px',
              border: '1px solid rgba(0,212,255,0.15)',
              borderLeft: '3px solid var(--accent-cyan)',
              fontSize: 13, lineHeight: 1.7, color: 'var(--text-secondary)',
              whiteSpace: 'pre-wrap'
            }}>
              {alert.ai_analysis}
            </div>
          ) : (
            <div className="flex items-center gap-3" style={{ color: 'var(--text-muted)', fontSize: 13 }}>
              <Brain size={20} style={{ opacity: 0.4 }} />
              <span>No AI analysis available. Configure GEMINI_API_KEY or OPENAI_API_KEY to enable.</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
