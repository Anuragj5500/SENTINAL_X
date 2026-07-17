import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, MessageSquare, Clock, Send } from 'lucide-react';
import { incidentsAPI } from '../api/client';
import toast from 'react-hot-toast';

const STATUS_FLOW = ['open','assigned','investigating','containment','recovery','resolved','closed'];

export default function IncidentDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [incident, setIncident] = useState(null);
  const [comments, setComments] = useState([]);
  const [newComment, setNewComment] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([incidentsAPI.get(id), incidentsAPI.getComments(id)])
      .then(([incRes, commRes]) => { setIncident(incRes.data); setComments(commRes.data); })
      .catch(() => toast.error('Failed to load incident'))
      .finally(() => setLoading(false));
  }, [id]);

  const updateStatus = async (status) => {
    try {
      const res = await incidentsAPI.update(id, { status });
      setIncident(res.data);
      toast.success(`Status → ${status}`);
    } catch { toast.error('Failed'); }
  };

  const addComment = async (e) => {
    e.preventDefault();
    if (!newComment.trim()) return;
    try {
      const res = await incidentsAPI.addComment(id, newComment);
      setComments((c) => [...c, res.data]);
      setNewComment('');
    } catch { toast.error('Failed to add comment'); }
  };

  if (loading) return <div className="page-loader"><div className="spinner" style={{ width: 36, height: 36 }} /></div>;
  if (!incident) return <div className="empty-state"><p>Incident not found</p></div>;

  const currentIdx = STATUS_FLOW.indexOf(incident.status);

  return (
    <div>
      <button className="btn btn-ghost btn-sm" onClick={() => navigate('/incidents')} style={{ marginBottom: 20 }}>
        <ArrowLeft size={14} /> Back
      </button>

      {/* Header */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-header">
          <div>
            <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
              <span className={`badge ${incident.severity}`}>{incident.severity}</span>
              <span className={`badge ${incident.status}`}>{incident.status.replace('_',' ')}</span>
              <span style={{
                padding: '2px 8px', borderRadius: 4, fontSize: 11, fontWeight: 700,
                background: 'var(--bg-hover)', color: 'var(--text-muted)'
              }}>P{incident.priority}</span>
            </div>
            <h2 style={{ fontSize: 18, fontWeight: 700 }}>{incident.title}</h2>
          </div>
        </div>
        <div className="card-body">
          <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 16 }}>{incident.description}</p>

          {/* Status Flow */}
          <div style={{ marginBottom: 16 }}>
            <div className="text-xs text-muted" style={{ marginBottom: 8 }}>Workflow Status</div>
            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
              {STATUS_FLOW.map((s, i) => (
                <button
                  key={s}
                  onClick={() => updateStatus(s)}
                  className="btn btn-sm"
                  style={{
                    background: i <= currentIdx ? 'rgba(0,212,255,0.15)' : 'var(--bg-hover)',
                    color: i <= currentIdx ? 'var(--accent-cyan)' : 'var(--text-muted)',
                    border: i === currentIdx ? '1px solid var(--accent-cyan)' : '1px solid var(--border)',
                    fontWeight: i === currentIdx ? 700 : 400,
                  }}
                >{s.replace('_',' ')}</button>
              ))}
            </div>
          </div>

          <div className="grid-3" style={{ fontSize: 13 }}>
            {incident.mitre_techniques?.length > 0 && (
              <div>
                <div className="text-xs text-muted">MITRE Techniques</div>
                <div className="font-mono" style={{ color: 'var(--accent-cyan)' }}>
                  {incident.mitre_techniques.join(', ')}
                </div>
              </div>
            )}
            {incident.affected_assets?.length > 0 && (
              <div>
                <div className="text-xs text-muted">Affected Assets</div>
                <div>{incident.affected_assets.join(', ')}</div>
              </div>
            )}
            {incident.tags?.length > 0 && (
              <div>
                <div className="text-xs text-muted">Tags</div>
                <div>{incident.tags.join(', ')}</div>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="grid-2">
        {/* Timeline */}
        <div className="card">
          <div className="card-header">
            <span className="card-title"><Clock size={14} /> Timeline</span>
          </div>
          <div className="card-body">
            <div className="timeline">
              {(incident.timeline || []).map((t, i) => (
                <div key={i} className="timeline-item">
                  <div className="timeline-time">{new Date(t.timestamp).toLocaleString()}</div>
                  <div className="timeline-text">{t.action} {t.user ? `— ${t.user}` : ''}</div>
                </div>
              ))}
              {(!incident.timeline || incident.timeline.length === 0) && (
                <div className="text-sm text-muted">No timeline entries</div>
              )}
            </div>
          </div>
        </div>

        {/* Comments */}
        <div className="card">
          <div className="card-header">
            <span className="card-title"><MessageSquare size={14} /> Comments ({comments.length})</span>
          </div>
          <div className="card-body">
            <div style={{ maxHeight: 280, overflowY: 'auto', marginBottom: 16 }}>
              {comments.map((c) => (
                <div key={c.id} style={{
                  background: 'var(--bg-base)', borderRadius: 8, padding: '10px 12px',
                  marginBottom: 8, border: '1px solid var(--border)'
                }}>
                  <div className="text-xs text-muted" style={{ marginBottom: 4 }}>
                    {new Date(c.created_at).toLocaleString()}
                  </div>
                  <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>{c.content}</div>
                </div>
              ))}
              {comments.length === 0 && <div className="text-sm text-muted">No comments yet</div>}
            </div>
            <form onSubmit={addComment} style={{ display: 'flex', gap: 8 }}>
              <input
                className="input"
                placeholder="Add a comment…"
                value={newComment}
                onChange={(e) => setNewComment(e.target.value)}
                style={{ flex: 1 }}
              />
              <button type="submit" className="btn btn-primary btn-sm">
                <Send size={13} />
              </button>
            </form>
          </div>
        </div>
      </div>

      {/* AI Summary */}
      {incident.ai_summary && (
        <div className="card" style={{ marginTop: 16 }}>
          <div className="card-header">
            <span className="card-title">🤖 AI Incident Summary</span>
          </div>
          <div className="card-body">
            <div style={{
              background: 'var(--bg-base)', borderRadius: 8, padding: 16,
              border: '1px solid rgba(0,212,255,0.15)', borderLeft: '3px solid var(--accent-cyan)',
              fontSize: 13, color: 'var(--text-secondary)', whiteSpace: 'pre-wrap', lineHeight: 1.7
            }}>{incident.ai_summary}</div>
          </div>
        </div>
      )}
    </div>
  );
}
