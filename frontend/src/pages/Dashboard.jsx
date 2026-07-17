import { useEffect, useState } from 'react';
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, Cell, PieChart, Pie, Legend
} from 'recharts';
import { AlertTriangle, Folder, Monitor, Activity, Zap, Shield, TrendingUp } from 'lucide-react';
import { dashboardAPI } from '../api/client';
import toast from 'react-hot-toast';

const SEVERITY_COLORS = {
  critical: '#ff3b5c', high: '#ff8c42', medium: '#f5c842', low: '#42d4a0', info: '#60a5fa'
};

const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload?.length) {
    return (
      <div style={{
        background: '#131c2e', border: '1px solid #1e2d45', borderRadius: 8,
        padding: '10px 14px', fontSize: 12
      }}>
        <div style={{ color: '#8ca0bc', marginBottom: 4 }}>{label}</div>
        {payload.map((p) => (
          <div key={p.dataKey} style={{ color: p.color, fontWeight: 600 }}>
            {p.name}: {p.value}
          </div>
        ))}
      </div>
    );
  }
  return null;
};

export default function DashboardPage() {
  const [stats, setStats] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      dashboardAPI.getStats(),
      dashboardAPI.getTimeline(7),
    ]).then(([statsRes, timelineRes]) => {
      setStats(statsRes.data);
      setTimeline(timelineRes.data);
    }).catch(() => toast.error('Failed to load dashboard')).finally(() => setLoading(false));
  }, []);

  if (loading) return (
    <div className="page-loader">
      <div className="spinner" style={{ width: 36, height: 36 }} />
    </div>
  );

  const pieData = stats ? Object.entries(stats.alerts_by_severity).map(([name, value]) => ({ name, value })) : [];
  const mitreMax = Math.max(...(stats?.mitre_heatmap || []).map((m) => m.count), 1);

  const getHeatClass = (count) => {
    if (count === 0) return 'heat-0';
    const ratio = count / mitreMax;
    if (ratio < 0.33) return 'heat-1';
    if (ratio < 0.66) return 'heat-2';
    return 'heat-3';
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 800, color: 'var(--text-primary)' }}>
            Security Dashboard
          </h1>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 2 }}>
            Real-time threat monitoring & security posture overview
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="live-dot" />
          <span style={{ fontSize: 12, color: 'var(--success)', fontWeight: 600 }}>LIVE</span>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="stats-grid">
        {[
          { label: 'Open Alerts',       value: stats?.open_alerts || 0,     cls: 'critical', icon: AlertTriangle },
          { label: 'Critical Alerts',   value: stats?.critical_alerts || 0, cls: 'critical', icon: Zap },
          { label: 'Active Incidents',  value: stats?.open_incidents || 0,  cls: 'high',     icon: Folder },
          { label: 'Total Assets',      value: stats?.total_assets || 0,    cls: 'info',     icon: Monitor },
          { label: 'Events Today',      value: stats?.events_today || 0,    cls: 'cyan',     icon: Activity },
          { label: 'MTTD (min)',         value: stats?.mean_time_to_detect?.toFixed(1) || '—', cls: 'success', icon: TrendingUp },
        ].map((s) => (
          <div key={s.label} className={`stat-card ${s.cls}`}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div className="stat-label">{s.label}</div>
              <s.icon size={18} style={{ color: 'var(--text-muted)' }} />
            </div>
            <div className="stat-value">{typeof s.value === 'number' ? s.value.toLocaleString() : s.value}</div>
          </div>
        ))}
      </div>

      {/* Charts Row */}
      <div className="charts-grid">
        {/* Alert Timeline */}
        <div className="card">
          <div className="card-header">
            <span className="card-title"><Activity size={15} /> Alert Volume (7 days)</span>
          </div>
          <div className="card-body">
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={timeline}>
                <defs>
                  <linearGradient id="critGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ff3b5c" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#ff3b5c" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="highGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ff8c42" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#ff8c42" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="date" tick={{ fontSize: 10, fill: '#4a5c73' }} />
                <YAxis tick={{ fontSize: 10, fill: '#4a5c73' }} />
                <Tooltip content={<CustomTooltip />} />
                <Area type="monotone" dataKey="critical" stroke="#ff3b5c" fill="url(#critGrad)" name="Critical" />
                <Area type="monotone" dataKey="high"     stroke="#ff8c42" fill="url(#highGrad)" name="High" />
                <Area type="monotone" dataKey="medium"   stroke="#f5c842" fill="none" name="Medium" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Alerts by Severity Pie */}
        <div className="card">
          <div className="card-header">
            <span className="card-title"><Shield size={15} /> Alerts by Severity</span>
          </div>
          <div className="card-body">
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" innerRadius={55} outerRadius={85}
                     dataKey="value" nameKey="name" paddingAngle={3}>
                  {pieData.map((entry) => (
                    <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] || '#60a5fa'} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
                <Legend iconSize={8} wrapperStyle={{ fontSize: 11, color: '#8ca0bc' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Bottom Row */}
      <div className="grid-2" style={{ gap: 16 }}>
        {/* Top Attackers */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">🎯 Top Attackers (Source IPs)</span>
          </div>
          <div className="card-body" style={{ padding: '12px 16px' }}>
            {(stats?.top_attackers || []).slice(0, 6).map((att, i) => (
              <div key={att.ip} className="flex items-center gap-3" style={{ padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
                <span style={{ fontSize: 11, color: 'var(--text-muted)', width: 18 }}>#{i + 1}</span>
                <span className="font-mono" style={{ flex: 1 }}>{att.ip}</span>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <div style={{
                    height: 4, width: `${Math.min(att.count / (stats.top_attackers[0]?.count || 1) * 80, 80)}px`,
                    background: 'var(--critical)', borderRadius: 2
                  }} />
                  <span style={{ fontSize: 12, color: 'var(--critical)', fontWeight: 700, width: 28 }}>{att.count}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* MITRE Heatmap */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">🗺️ MITRE ATT&amp;CK Coverage</span>
          </div>
          <div className="card-body">
            <div className="mitre-grid">
              {(stats?.mitre_heatmap || []).map((m) => (
                <div
                  key={m.technique}
                  className={`mitre-cell ${getHeatClass(m.count)}`}
                  title={`${m.tactic} — ${m.technique}: ${m.count} alerts`}
                >
                  {m.technique}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Recent Alerts Table */}
      <div className="card" style={{ marginTop: 16 }}>
        <div className="card-header">
          <span className="card-title"><AlertTriangle size={15} /> Recent Alerts</span>
        </div>
        <div className="table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
          <table>
            <thead>
              <tr>
                <th>Title</th>
                <th>Severity</th>
                <th>Hostname</th>
                <th>Source IP</th>
                <th>MITRE</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {(stats?.recent_alerts || []).map((a) => (
                <tr key={a.id}>
                  <td style={{ maxWidth: 200, color: 'var(--text-primary)', fontWeight: 500 }}
                      className="truncate">{a.title}</td>
                  <td><span className={`badge ${a.severity}`}>{a.severity}</span></td>
                  <td className="font-mono">{a.hostname || '—'}</td>
                  <td className="font-mono">{a.source_ip || '—'}</td>
                  <td className="font-mono">{a.mitre_technique || '—'}</td>
                  <td className="text-xs text-muted">
                    {a.created_at ? new Date(a.created_at).toLocaleTimeString() : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
