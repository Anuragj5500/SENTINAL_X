import { useState, useEffect, useCallback } from 'react';
import { Shield, Play, Trash, ToggleLeft, ToggleRight, Plus, RefreshCw, BarChart } from 'lucide-react';
import { rulesAPI } from '../api/client';
import toast from 'react-hot-toast';

export default function RulesPage() {
  const [rules, setRules] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState(null);
  const [showCreate, setShowCreate] = useState(false);
  const [newRule, setNewRule] = useState({
    name: '', description: '', severity: 'medium', rule_type: 'signature', logic: '{}', mitre_technique: '', mitre_tactic: ''
  });

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await rulesAPI.list({ page, page_size: 50 });
      setRules(res.data.items || []);
      setTotal(res.data.total || 0);

      const statsRes = await rulesAPI.stats();
      setStats(statsRes.data);
    } catch {
      toast.error('Failed to load rules');
    } finally {
      setLoading(false);
    }
  }, [page]);

  useEffect(() => {
    load();
  }, [load]);

  const handleToggle = async (id) => {
    try {
      const res = await rulesAPI.toggle(id);
      toast.success(res.data.message);
      load();
    } catch {
      toast.error('Failed to toggle rule');
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Are you sure you want to delete this rule?')) return;
    try {
      await rulesAPI.delete(id);
      toast.success('Rule deleted');
      load();
    } catch {
      toast.error('Failed to delete rule');
    }
  };

  const handleCreate = async (e) => {
    e.preventDefault();
    try {
      let parsedLogic = {};
      try {
        parsedLogic = JSON.parse(newRule.logic);
      } catch {
        toast.error('Invalid JSON in Logic field');
        return;
      }

      await rulesAPI.create({
        ...newRule,
        logic: parsedLogic
      });
      toast.success('Rule created');
      setShowCreate(false);
      setNewRule({
        name: '', description: '', severity: 'medium', rule_type: 'signature', logic: '{}', mitre_technique: '', mitre_tactic: ''
      });
      load();
    } catch {
      toast.error('Failed to create rule');
    }
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 800 }}>Detection Rules</h1>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 2 }}>
            {total} rules configured
          </p>
        </div>
        <div className="flex gap-2">
          <button onClick={load} className="btn btn-ghost btn-sm">
            <RefreshCw size={14} />
          </button>
          <button className="btn btn-primary btn-sm" onClick={() => setShowCreate(true)}>
            <Plus size={14} /> Create Rule
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      {stats && (
        <div className="stats-grid" style={{ marginBottom: 20 }}>
          <div className="stat-card cyan">
            <div className="stat-label">Total Rules</div>
            <div className="stat-value">{stats.total_rules}</div>
          </div>
          <div className="stat-card success">
            <div className="stat-label">Active Rules</div>
            <div className="stat-value">{stats.active_rules}</div>
          </div>
          <div className="stat-card critical">
            <div className="stat-label">Disabled Rules</div>
            <div className="stat-value">{stats.disabled_rules}</div>
          </div>
        </div>
      )}

      {/* Create Modal */}
      {showCreate && (
        <div style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000
        }}>
          <div className="card" style={{ width: 500, maxHeight: '90vh', overflowY: 'auto' }}>
            <div className="card-header">
              <span className="card-title">Create Detection Rule</span>
              <button className="btn btn-ghost btn-sm" onClick={() => setShowCreate(false)}>✕</button>
            </div>
            <form onSubmit={handleCreate}>
              <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div className="input-group">
                  <label className="input-label">Rule Name</label>
                  <input className="input" required value={newRule.name}
                    onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
                    placeholder="Brute Force Attempt" />
                </div>
                <div className="input-group">
                  <label className="input-label">Description</label>
                  <textarea className="input" value={newRule.description}
                    onChange={(e) => setNewRule({ ...newRule, description: e.target.value })}
                    placeholder="Rule description..." />
                </div>
                <div className="grid-2">
                  <div className="input-group">
                    <label className="input-label">Severity</label>
                    <select className="input" value={newRule.severity}
                      onChange={(e) => setNewRule({ ...newRule, severity: e.target.value })}>
                      {['critical','high','medium','low','info'].map((s) => <option key={s} value={s}>{s}</option>)}
                    </select>
                  </div>
                  <div className="input-group">
                    <label className="input-label">Rule Type</label>
                    <select className="input" value={newRule.rule_type}
                      onChange={(e) => setNewRule({ ...newRule, rule_type: e.target.value })}>
                      {['signature','threshold','custom'].map((t) => <option key={t} value={t}>{t}</option>)}
                    </select>
                  </div>
                </div>
                <div className="grid-2">
                  <div className="input-group">
                    <label className="input-label">MITRE Technique</label>
                    <input className="input" value={newRule.mitre_technique}
                      onChange={(e) => setNewRule({ ...newRule, mitre_technique: e.target.value })}
                      placeholder="T1110" />
                  </div>
                  <div className="input-group">
                    <label className="input-label">MITRE Tactic</label>
                    <input className="input" value={newRule.mitre_tactic}
                      onChange={(e) => setNewRule({ ...newRule, mitre_tactic: e.target.value })}
                      placeholder="Credential Access" />
                  </div>
                </div>
                <div className="input-group">
                  <label className="input-label">Logic (JSON Object)</label>
                  <textarea className="input" style={{ fontFamily: 'JetBrains Mono', fontSize: 12 }} rows={4}
                    value={newRule.logic}
                    onChange={(e) => setNewRule({ ...newRule, logic: e.target.value })} />
                </div>
                <div className="flex gap-2" style={{ justifyContent: 'flex-end', marginTop: 8 }}>
                  <button type="button" className="btn btn-ghost" onClick={() => setShowCreate(false)}>Cancel</button>
                  <button type="submit" className="btn btn-primary">Create</button>
                </div>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Rules Table */}
      <div className="table-wrapper">
        {loading ? (
          <div className="page-loader"><div className="spinner" /></div>
        ) : rules.length === 0 ? (
          <div className="empty-state"><Shield size={40} /><p>No rules configured</p></div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Rule Name</th>
                <th>Severity</th>
                <th>Type</th>
                <th>MITRE</th>
                <th>Triggers</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr key={rule.id}>
                  <td style={{ color: 'var(--text-primary)', fontWeight: 500 }}>
                    <div>{rule.name}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{rule.description}</div>
                  </td>
                  <td><span className={`badge ${rule.severity}`}>{rule.severity}</span></td>
                  <td><span className="badge info">{rule.rule_type}</span></td>
                  <td className="font-mono" style={{ color: 'var(--accent-cyan)' }}>{rule.mitre_technique || '—'}</td>
                  <td style={{ fontWeight: 700 }}>{rule.trigger_count || 0}</td>
                  <td>
                    <button onClick={() => handleToggle(rule.id)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: rule.enabled ? 'var(--success)' : 'var(--text-muted)' }}>
                      {rule.enabled ? <ToggleRight size={24} /> : <ToggleLeft size={24} />}
                    </button>
                  </td>
                  <td>
                    <button className="btn btn-danger btn-sm" onClick={() => handleDelete(rule.id)}>
                      <Trash size={12} />
                    </button>
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
