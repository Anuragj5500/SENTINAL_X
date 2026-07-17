import { useState, useEffect, useRef } from 'react';
import { Shield, ShieldAlert, ShieldCheck, Search, X, HelpCircle } from 'lucide-react';
import { rulesAPI } from '../api/client';
import toast from 'react-hot-toast';

export default function MitreMatrixPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [selectedTech, setSelectedTech] = useState(null);

  useEffect(() => {
    rulesAPI.mitreMatrix()
      .then((res) => {
        setData(res.data);
      })
      .catch(() => {
        toast.error('Failed to load MITRE ATT&CK Matrix data');
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  if (loading) {
    return <div className="page-loader"><div className="spinner" /></div>;
  }

  if (!data) {
    return <div className="empty-state"><HelpCircle size={40} /><p>No MITRE data available</p></div>;
  }

  // Calculate stats
  let totalTechs = 0;
  let coveredTechs = 0;
  let activeThreats = 0;

  Object.values(data.matrix).forEach((techList) => {
    techList.forEach((tech) => {
      totalTechs++;
      if (tech.covered) coveredTechs++;
      if (tech.alerts_count > 0) activeThreats++;
    });
  });

  const coverageRate = totalTechs > 0 ? Math.round((coveredTechs / totalTechs) * 100) : 0;

  return (
    <div className="mitre-matrix-container">
      {/* Page Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 800 }}>MITRE ATT&CK® Matrix</h1>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 2 }}>
            Real-time visual map of detection rule coverage and active alerts across tactics.
          </p>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="stats-grid mb-6">
        <div className="stat-card cyan">
          <div className="stat-label">Coverage Rate</div>
          <div className="stat-value">{coverageRate}%</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
            {coveredTechs} of {totalTechs} techniques covered
          </div>
        </div>
        <div className="stat-card info">
          <div className="stat-label">Active Detection Rules</div>
          <div className="stat-value">{coveredTechs}</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
            With MITRE techniques mapped
          </div>
        </div>
        <div className="stat-card critical">
          <div className="stat-label">Techniques Under Attack</div>
          <div className="stat-value">{activeThreats}</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
            Anomalies/Alerts in the last 7 days
          </div>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="card mb-6" style={{ padding: 12 }}>
        <div className="flex items-center gap-4" style={{ flexWrap: 'wrap' }}>
          <div className="search-bar" style={{ flex: 1, minWidth: 260 }}>
            <Search size={14} className="search-icon" />
            <input
              className="input"
              placeholder="Filter by Technique Name or ID (e.g., PowerShell, T1566)..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <div className="flex gap-4 text-xs" style={{ alignItems: 'center' }}>
            <div className="flex items-center gap-1.5">
              <span className="legend-indicator" style={{ background: 'rgba(255, 59, 92, 0.15)', border: '1px solid var(--critical)', boxShadow: '0 0 8px rgba(255, 59, 92, 0.2)' }} />
              <span style={{ color: 'var(--text-primary)' }}>Active Threat (Alerts)</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="legend-indicator" style={{ background: 'rgba(0, 212, 255, 0.08)', border: '1px solid var(--accent-cyan)', boxShadow: '0 0 8px rgba(0, 212, 255, 0.15)' }} />
              <span style={{ color: 'var(--text-primary)' }}>Covered (Active Rule)</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="legend-indicator" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} />
              <span style={{ color: 'var(--text-secondary)' }}>No Coverage</span>
            </div>
          </div>
        </div>
      </div>

      {/* Matrix Board */}
      <div className="mitre-matrix-board">
        {data.tactics.map((tactic) => {
          const techniques = data.matrix[tactic] || [];
          const filtered = techniques.filter(t => 
            !search || 
            t.name.toLowerCase().includes(search.toLowerCase()) || 
            t.id.toLowerCase().includes(search.toLowerCase())
          );

          return (
            <div key={tactic} className="mitre-tactic-column">
              <div className="mitre-tactic-header">
                <div className="tactic-title">{tactic}</div>
                <div className="tactic-count">{filtered.length} techs</div>
              </div>
              <div className="mitre-techniques-list">
                {filtered.map((tech) => {
                  let cardClass = "mitre-tech-card";
                  if (tech.alerts_count > 0) {
                    cardClass += " alert-threat";
                  } else if (tech.covered) {
                    cardClass += " rule-covered";
                  }

                  return (
                    <div
                      key={tech.id}
                      className={cardClass}
                      onClick={() => setSelectedTech(tech)}
                    >
                      <div className="tech-id">{tech.id}</div>
                      <div className="tech-name">{tech.name}</div>
                      {tech.alerts_count > 0 && (
                        <div className="tech-badge alert-pulse">
                          <ShieldAlert size={10} /> {tech.alerts_count}
                        </div>
                      )}
                      {tech.covered && tech.alerts_count === 0 && (
                        <div className="tech-badge covered">
                          <ShieldCheck size={10} /> Covered
                        </div>
                      )}
                    </div>
                  );
                })}
                {filtered.length === 0 && (
                  <div className="mitre-empty-column">No matches</div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Detail Modal */}
      {selectedTech && (
        <div className="modal-overlay" onClick={() => setSelectedTech(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 600 }}>
            <div className="modal-header">
              <div>
                <span className="tech-modal-id">{selectedTech.id}</span>
                <h3 className="modal-title" style={{ marginTop: 4 }}>{selectedTech.name}</h3>
              </div>
              <button className="btn btn-ghost btn-icon" onClick={() => setSelectedTech(null)}>
                <X size={16} />
              </button>
            </div>
            <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {/* Status Header */}
              <div className="flex gap-4">
                <div className="flex-1 info-box" style={{ background: selectedTech.covered ? 'rgba(0,212,255,0.06)' : 'transparent', border: `1px solid ${selectedTech.covered ? 'var(--accent-cyan)' : 'var(--border)'}` }}>
                  <div className="info-box-label">Detection Status</div>
                  <div className="info-box-value" style={{ color: selectedTech.covered ? 'var(--accent-cyan)' : 'var(--text-secondary)' }}>
                    {selectedTech.covered ? '🔒 Protected (Active Rules)' : '⚠️ Uncovered'}
                  </div>
                </div>
                <div className="flex-1 info-box" style={{ background: selectedTech.alerts_count > 0 ? 'rgba(255,59,92,0.06)' : 'transparent', border: `1px solid ${selectedTech.alerts_count > 0 ? 'var(--critical)' : 'var(--border)'}` }}>
                  <div className="info-box-label">Active Incidents (Last 7d)</div>
                  <div className="info-box-value" style={{ color: selectedTech.alerts_count > 0 ? 'var(--critical)' : 'var(--success)' }}>
                    {selectedTech.alerts_count > 0 ? `🚨 ${selectedTech.alerts_count} Alerts` : '🟢 Clear'}
                  </div>
                </div>
              </div>

              {/* Rules List */}
              <div>
                <h4 style={{ fontSize: 13, fontWeight: 700, marginBottom: 8, color: 'var(--text-primary)' }}>
                  🛡️ Active Detection Rules ({selectedTech.rules?.length || 0})
                </h4>
                {selectedTech.rules && selectedTech.rules.length > 0 ? (
                  <div className="rules-modal-list">
                    {selectedTech.rules.map((rule) => (
                      <div key={rule.id} className="rule-item-mini">
                        <span className={`badge ${rule.severity}`} style={{ fontSize: 10 }}>{rule.severity}</span>
                        <span className="rule-item-name">{rule.name}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="empty-mini-box">No detection rules cover this technique.</div>
                )}
              </div>

              {/* Action recommendation */}
              {!selectedTech.covered && (
                <div className="tip-alert-box">
                  <strong>💡 Coverage Advice:</strong> Creating a custom detection rule mapping <code>mitre_technique: "{selectedTech.id}"</code> will resolve this coverage gap.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Styles for MITRE matrix */}
      <style>{`
        .mitre-matrix-container {
          display: flex;
          flex-direction: column;
          height: calc(100vh - 120px);
          max-width: 100%;
          overflow: hidden;
        }
        .top-scrollbar-mirror::-webkit-scrollbar {
          height: 6px;
        }
        .top-scrollbar-mirror::-webkit-scrollbar-track {
          background: rgba(19, 28, 46, 0.5);
          border-radius: 3px;
        }
        .top-scrollbar-mirror::-webkit-scrollbar-thumb {
          background: var(--border-bright);
          border-radius: 3px;
        }
        .mitre-matrix-board::-webkit-scrollbar {
          height: 6px;
        }
        .mitre-matrix-board::-webkit-scrollbar-track {
          background: rgba(19, 28, 46, 0.5);
          border-radius: 3px;
        }
        .mitre-matrix-board::-webkit-scrollbar-thumb {
          background: var(--border-bright);
          border-radius: 3px;
        }
        .mitre-matrix-board {
          display: flex;
          gap: 12px;
          overflow: auto; /* Enable both horizontal and vertical scrolling */
          padding-bottom: 12px;
          flex: 1;
          width: 100%;
        }
        .mitre-tactic-column {
          width: 200px;
          flex-shrink: 0;
          display: flex;
          flex-direction: column;
          background: var(--bg-surface);
          border: 1px solid var(--border);
          border-radius: var(--radius-md);
          overflow: visible; /* Show full height techniques without clipping */
          height: fit-content;
        }
        .mitre-tactic-header {
          padding: 12px;
          background: var(--bg-card);
          border-bottom: 1px solid var(--border);
          display: flex;
          justify-content: space-between;
          align-items: center;
          position: sticky;
          top: 0;
          z-index: 10;
          border-top-left-radius: var(--radius-md);
          border-top-right-radius: var(--radius-md);
        }
        .tactic-title {
          font-weight: 700;
          font-size: 11px;
          text-transform: uppercase;
          letter-spacing: 0.5px;
          color: var(--text-primary);
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .tactic-count {
          font-size: 10px;
          color: var(--text-secondary);
        }
        .mitre-techniques-list {
          padding: 8px;
          display: flex;
          flex-direction: column;
          gap: 8px;
          overflow-y: visible; /* Prevent individual column scrollbars */
          flex: 1;
        }
        .mitre-tech-card {
          padding: 10px;
          background: var(--bg-card);
          border: 1px solid var(--border);
          border-radius: var(--radius-sm);
          cursor: pointer;
          transition: all var(--transition);
          display: flex;
          flex-direction: column;
          gap: 4px;
        }
        .mitre-tech-card:hover {
          border-color: var(--border-bright);
          transform: translateY(-1px);
        }
        .tech-id {
          font-family: 'JetBrains Mono', monospace;
          font-size: 10px;
          color: var(--text-secondary);
          font-weight: 500;
        }
        .tech-name {
          font-size: 12px;
          font-weight: 500;
          color: var(--text-primary);
          line-height: 1.3;
        }
        .tech-badge {
          display: inline-flex;
          align-items: center;
          gap: 4px;
          font-size: 9px;
          font-weight: 600;
          padding: 2px 6px;
          border-radius: 4px;
          align-self: flex-start;
          margin-top: 4px;
        }
        .tech-badge.covered {
          background: rgba(0, 212, 255, 0.1);
          color: var(--accent-cyan);
        }
        .tech-badge.alert-threat {
          background: rgba(255, 59, 92, 0.15);
          color: var(--critical);
        }
        .mitre-tech-card.rule-covered {
          border-color: var(--accent-cyan);
          background: rgba(0, 212, 255, 0.04);
          box-shadow: 0 0 10px rgba(0, 212, 255, 0.05);
        }
        .mitre-tech-card.rule-covered:hover {
          background: rgba(0, 212, 255, 0.08);
          box-shadow: var(--glow-cyan);
        }
        .mitre-tech-card.alert-threat {
          border-color: var(--critical);
          background: rgba(255, 59, 92, 0.08);
          box-shadow: 0 0 10px rgba(255, 59, 92, 0.08);
        }
        .mitre-tech-card.alert-threat:hover {
          background: rgba(255, 59, 92, 0.15);
          box-shadow: var(--glow-red);
        }
        .alert-pulse {
          background: rgba(255, 59, 92, 0.2);
          color: var(--critical);
          animation: pulse 2s infinite;
        }
        @keyframes pulse {
          0% { box-shadow: 0 0 0 0 rgba(255, 59, 92, 0.4); }
          70% { box-shadow: 0 0 0 6px rgba(255, 59, 92, 0); }
          100% { box-shadow: 0 0 0 0 rgba(255, 59, 92, 0); }
        }
        .legend-indicator {
          width: 12px; height: 12px;
          border-radius: 3px;
          display: inline-block;
        }
        .mitre-empty-column {
          text-align: center;
          font-size: 11px;
          color: var(--text-muted);
          padding: 20px 0;
        }
        .tech-modal-id {
          font-family: 'JetBrains Mono', monospace;
          font-size: 11px;
          color: var(--accent-cyan);
          font-weight: 700;
        }
        .info-box {
          padding: 12px;
          border-radius: var(--radius-sm);
        }
        .info-box-label {
          font-size: 10px;
          text-transform: uppercase;
          color: var(--text-secondary);
          margin-bottom: 4px;
        }
        .info-box-value {
          font-size: 14px;
          font-weight: 700;
        }
        .rule-item-mini {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 8px 12px;
          background: var(--bg-surface);
          border: 1px solid var(--border);
          border-radius: var(--radius-sm);
          margin-bottom: 6px;
        }
        .rule-item-name {
          font-size: 12px;
          font-weight: 500;
          color: var(--text-primary);
        }
        .empty-mini-box {
          font-size: 12px;
          color: var(--text-secondary);
          text-align: center;
          padding: 16px;
          background: var(--bg-surface);
          border: 1px dashed var(--border);
          border-radius: var(--radius-sm);
        }
        .tip-alert-box {
          padding: 12px;
          background: rgba(245, 158, 11, 0.06);
          border: 1px solid var(--warning);
          border-radius: var(--radius-sm);
          font-size: 11px;
          color: var(--text-secondary);
        }
      `}</style>
    </div>
  );
}
