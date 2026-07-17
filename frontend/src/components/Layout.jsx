import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import { useState, useEffect } from 'react';
import {
  LayoutDashboard, AlertTriangle, Folder, Monitor,
  Search, Shield, Zap, Globe, Bug, FileText,
  Settings, LogOut, Bell, User, ChevronDown, Activity,
  Grid, Network
} from 'lucide-react';
import useAuthStore from '../store/authStore';
import { alertsAPI } from '../api/client';

const navItems = [
  { to: '/dashboard',       icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/alerts',          icon: AlertTriangle,   label: 'Alerts',     badge: true },
  { to: '/incidents',       icon: Folder,          label: 'Incidents' },
  { to: '/assets',          icon: Monitor,         label: 'Assets' },
  { section: 'Analysis' },
  { to: '/hunt',            icon: Search,          label: 'Threat Hunt' },
  { to: '/mitre',           icon: Grid,            label: 'MITRE Matrix' },
  { to: '/topology',        icon: Network,         label: 'Network Topology' },
  { to: '/rules',           icon: Shield,          label: 'Detection Rules' },
  { to: '/soar',            icon: Zap,             label: 'SOAR' },
  { to: '/threat-intel',    icon: Globe,           label: 'Threat Intel' },
  { section: 'Risk' },
  { to: '/vulnerabilities', icon: Bug,             label: 'Vulnerabilities' },
  { to: '/reports',         icon: FileText,        label: 'Reports' },
  { section: 'Admin' },
  { to: '/admin',           icon: Settings,        label: 'Admin Panel', adminOnly: true },
];

export default function Layout() {
  const { user, logout, isAdmin } = useAuthStore();
  const navigate = useNavigate();
  const [openAlerts, setOpenAlerts] = useState(0);
  const [wsStatus, setWsStatus] = useState('connecting');

  useEffect(() => {
    alertsAPI.summary().then((res) => {
      const byStatus = res.data?.by_status || {};
      setOpenAlerts(byStatus.open || 0);
    }).catch(() => {});
  }, []);

  // WebSocket for live alerts
  useEffect(() => {
    const wsUrl = (import.meta.env.VITE_API_URL || 'http://localhost:8000')
      .replace('http', 'ws')
      .replace('/api/v1', '') + '/ws/alerts';

    let ws;
    let reconnectTimeout;

    const connect = () => {
      ws = new WebSocket(wsUrl);
      ws.onopen = () => setWsStatus('connected');
      ws.onclose = () => {
        setWsStatus('disconnected');
        reconnectTimeout = setTimeout(connect, 5000);
      };
      ws.onerror = () => setWsStatus('error');
      ws.onmessage = (e) => {
        const msg = JSON.parse(e.data);
        if (msg.type === 'new_alert') {
          setOpenAlerts((n) => n + 1);
        }
      };
      // Keep-alive ping
      const ping = setInterval(() => { if (ws.readyState === 1) ws.send('ping'); }, 30000);
      ws._ping = ping;
    };
    connect();

    return () => {
      clearTimeout(reconnectTimeout);
      if (ws) {
        clearInterval(ws._ping);
        ws.close();
      }
    };
  }, []);

  const handleLogout = () => { logout(); navigate('/login'); };

  return (
    <div className="app-layout">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-logo">
          <div className="logo-icon">🛡️</div>
          <div>
            <div className="logo-text">SentinelX</div>
            <div className="logo-sub">SIEM Platform</div>
          </div>
        </div>

        <nav className="sidebar-nav">
          {navItems.map((item, i) => {
            if (item.section) {
              return <div key={i} className="nav-section-label">{item.section}</div>;
            }
            if (item.adminOnly && !isAdmin()) return null;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
              >
                <item.icon size={16} />
                {item.label}
                {item.badge && openAlerts > 0 && (
                  <span className="nav-badge">{openAlerts > 99 ? '99+' : openAlerts}</span>
                )}
              </NavLink>
            );
          })}
        </nav>

        {/* User section */}
        <div style={{ padding: '12px', borderTop: '1px solid var(--border)' }}>
          <div className="flex items-center gap-2" style={{ marginBottom: '8px' }}>
            <div style={{
              width: 32, height: 32, borderRadius: '50%',
              background: 'linear-gradient(135deg, var(--accent-cyan), var(--accent-blue))',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 12, fontWeight: 700, color: '#000'
            }}>
              {(user?.username || 'U')[0].toUpperCase()}
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)' }}
                   className="truncate">{user?.username}</div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                {user?.role?.replace('_', ' ')}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1" title={`WebSocket: ${wsStatus}`}>
              <div className="live-dot" style={{
                background: wsStatus === 'connected' ? 'var(--success)' : 'var(--text-muted)'
              }} />
              <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                {wsStatus === 'connected' ? 'LIVE' : wsStatus.toUpperCase()}
              </span>
            </div>
            <button
              onClick={handleLogout}
              className="btn btn-ghost btn-sm"
              style={{ marginLeft: 'auto', padding: '4px 8px' }}
            >
              <LogOut size={13} /> Logout
            </button>
          </div>
        </div>
      </aside>

      {/* Main */}
      <div className="main-content">
        <header className="topbar">
          <div className="topbar-title">
            <Activity size={16} style={{ display: 'inline', marginRight: 6, color: 'var(--accent-cyan)' }} />
            Security Operations Center
          </div>
          <div className="topbar-right">
            <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              {new Date().toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric' })}
            </span>
          </div>
        </header>

        <main className="page-content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
