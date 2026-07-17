import { useState, useEffect } from 'react';
import { Zap, Play, CheckCircle, XCircle, Clock } from 'lucide-react';
import { soarAPI, alertsAPI } from '../api/client';
import toast from 'react-hot-toast';

export default function SOARPage() {
  const [playbooks, setPlaybooks] = useState([]);
  const [executions, setExecutions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState({});
  const [activeTab, setActiveTab] = useState('playbooks');

  const load = async () => {
    setLoading(true);
    try {
      const pbRes = await soarAPI.listPlaybooks();
      setPlaybooks(pbRes.data);

      const execRes = await soarAPI.listExecutions();
      setExecutions(execRes.data);
    } catch {
      toast.error('Failed to load SOAR data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const handleRun = async (playbookId) => {
    const alertId = prompt('Enter Alert ID to run playbook against (optional):') || undefined;

    setRunning((prev) => ({ ...prev, [playbookId]: true }));
    try {
      const res = await soarAPI.runPlaybook(playbookId, { alert_id: alertId });
      toast.success(`Playbook execution triggered successfully! Status: ${res.data.status}`);
      load();
    } catch {
      toast.error('Failed to run playbook');
    } finally {
      setRunning((prev) => ({ ...prev, [playbookId]: false }));
    }
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 800 }}>SOAR Automation</h1>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 2 }}>
            Security Orchestration, Automation, and Response playbooks
          </p>
        </div>
        <button onClick={load} className="btn btn-ghost btn-sm">Refresh</button>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 16, borderBottom: '1px solid var(--border)' }}>
        <button
          onClick={() => setActiveTab('playbooks')}
          className="btn btn-ghost"
          style={{
            borderBottom: activeTab === 'playbooks' ? '2px solid var(--accent-cyan)' : 'none',
            color: activeTab === 'playbooks' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            borderRadius: 0,
            paddingBottom: 10,
          }}
        >
          Playbooks
        </button>
        <button
          onClick={() => setActiveTab('executions')}
          className="btn btn-ghost"
          style={{
            borderBottom: activeTab === 'executions' ? '2px solid var(--accent-cyan)' : 'none',
            color: activeTab === 'executions' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            borderRadius: 0,
            paddingBottom: 10,
          }}
        >
          Execution History
        </button>
      </div>

      {loading ? (
        <div className="page-loader"><div className="spinner" /></div>
      ) : activeTab === 'playbooks' ? (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: 16 }}>
          {playbooks.map((pb) => (
            <div key={pb.id} className="card">
              <div className="card-header">
                <div>
                  <h3 style={{ fontSize: 14, fontWeight: 700 }}>{pb.name}</h3>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>Trigger: {pb.trigger_type} ({pb.trigger_severity})</div>
                </div>
                <button
                  onClick={() => handleRun(pb.id)}
                  disabled={running[pb.id]}
                  className="btn btn-primary btn-sm btn-icon"
                >
                  <Play size={13} />
                </button>
              </div>
              <div className="card-body">
                <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 14 }}>{pb.description}</p>
                <div className="text-xs text-muted" style={{ marginBottom: 6 }}>Actions Sequence:</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {pb.actions?.map((act, idx) => (
                    <div key={idx} style={{
                      display: 'flex', alignItems: 'center', gap: 8,
                      background: 'var(--bg-hover)', padding: '6px 10px', borderRadius: 'var(--radius-sm)',
                      fontSize: 12, border: '1px solid var(--border)'
                    }}>
                      <Zap size={11} style={{ color: 'var(--accent-cyan)' }} />
                      <span style={{ fontWeight: 600, textTransform: 'capitalize' }}>{act.type.replace('_', ' ')}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="table-wrapper">
          {executions.length === 0 ? (
            <div className="empty-state"><Zap size={40} /><p>No playbook executions recorded</p></div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Execution ID</th>
                  <th>Playbook</th>
                  <th>Alert ID</th>
                  <th>Status</th>
                  <th>Started</th>
                  <th>Results</th>
                </tr>
              </thead>
              <tbody>
                {executions.map((ex) => (
                  <tr key={ex.id}>
                    <td className="font-mono text-xs">{ex.id}</td>
                    <td style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                      {playbooks.find((p) => p.id === ex.playbook_id)?.name || 'Unknown Playbook'}
                    </td>
                    <td className="font-mono text-xs">{ex.alert_id || '—'}</td>
                    <td>
                      <span className={`badge ${ex.status === 'completed' ? 'resolved' : ex.status === 'failed' ? 'critical' : 'investigating'}`}>
                        {ex.status}
                      </span>
                    </td>
                    <td className="text-xs text-muted">{new Date(ex.started_at).toLocaleString()}</td>
                    <td>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                        {ex.results?.map((res, i) => (
                          <div key={i} style={{ fontSize: 11 }}>
                            {res.success ? <CheckCircle size={10} style={{ color: 'var(--success)', display: 'inline', marginRight: 4 }} /> : <XCircle size={10} style={{ color: 'var(--critical)', display: 'inline', marginRight: 4 }} />}
                            <span style={{ textTransform: 'capitalize', fontWeight: 600 }}>{res.action}:</span> {res.result?.message || res.error || 'Done'}
                          </div>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
