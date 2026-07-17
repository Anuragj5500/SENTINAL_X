import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Eye, EyeOff, Lock } from 'lucide-react';
import { authAPI } from '../api/client';
import useAuthStore from '../store/authStore';
import toast from 'react-hot-toast';

export default function LoginPage() {
  const navigate = useNavigate();
  const { login } = useAuthStore();
  const [form, setForm] = useState({ username: '', password: '', totp_code: '' });
  const [showPass, setShowPass] = useState(false);
  const [loading, setLoading] = useState(false);
  const [showMFA, setShowMFA] = useState(false);

  const handleChange = (e) => setForm({ ...form, [e.target.name]: e.target.value });

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const payload = { username: form.username, password: form.password };
      if (showMFA) payload.totp_code = form.totp_code;

      const res = await authAPI.login(payload);
      const { access_token, user } = res.data;
      login(access_token, user);
      toast.success(`Welcome back, ${user.username}!`);
      navigate('/dashboard');
    } catch (err) {
      const msg = err.response?.data?.detail || 'Login failed';
      if (msg.includes('MFA') || msg.includes('TOTP')) {
        setShowMFA(true);
        toast.error('Enter your MFA code');
      } else {
        toast.error(msg);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <div className="login-card">
        {/* Logo */}
        <div className="flex flex-col items-center" style={{ marginBottom: 32, gap: 12 }}>
          <div style={{
            width: 60, height: 60,
            background: 'linear-gradient(135deg, var(--accent-cyan), var(--accent-blue))',
            borderRadius: 16,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 28,
            boxShadow: 'var(--glow-cyan)',
          }}>🛡️</div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 24, fontWeight: 800, letterSpacing: -0.5 }}>
              <span style={{
                background: 'linear-gradient(90deg, var(--accent-cyan), var(--accent-blue))',
                WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent'
              }}>Sentinel</span>
              <span style={{ color: 'var(--text-primary)' }}>X</span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
              Enterprise SIEM Platform
            </div>
          </div>
        </div>

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div className="input-group">
            <label className="input-label">Username</label>
            <input
              name="username"
              className="input"
              placeholder="admin"
              value={form.username}
              onChange={handleChange}
              required
              autoComplete="username"
            />
          </div>

          <div className="input-group">
            <label className="input-label">Password</label>
            <div style={{ position: 'relative' }}>
              <input
                name="password"
                type={showPass ? 'text' : 'password'}
                className="input"
                placeholder="••••••••••••"
                value={form.password}
                onChange={handleChange}
                required
                autoComplete="current-password"
                style={{ paddingRight: 40 }}
              />
              <button
                type="button"
                onClick={() => setShowPass(!showPass)}
                style={{
                  position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)',
                  background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer'
                }}
              >
                {showPass ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          {showMFA && (
            <div className="input-group">
              <label className="input-label">MFA Code (6 digits)</label>
              <input
                name="totp_code"
                className="input"
                placeholder="000000"
                value={form.totp_code}
                onChange={handleChange}
                maxLength={6}
                style={{ letterSpacing: 6, fontFamily: 'JetBrains Mono', textAlign: 'center' }}
              />
            </div>
          )}

          <button
            type="submit"
            className="btn btn-primary w-full"
            disabled={loading}
            style={{ justifyContent: 'center', marginTop: 8, padding: '12px' }}
          >
            {loading ? <div className="spinner" style={{ width: 16, height: 16 }} /> : <Lock size={16} />}
            {loading ? 'Authenticating...' : 'Sign In'}
          </button>
        </form>

        {/* Demo hint */}
        <div style={{
          marginTop: 24,
          padding: '12px',
          background: 'rgba(0,212,255,0.05)',
          border: '1px solid rgba(0,212,255,0.15)',
          borderRadius: 'var(--radius-sm)',
        }}>
          <div style={{ fontSize: 11, color: 'var(--accent-cyan)', fontWeight: 600, marginBottom: 4 }}>
            DEMO CREDENTIALS
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono' }}>
            admin / SentinelX@2024!<br />
            analyst / Analyst@2024!
          </div>
        </div>
      </div>
    </div>
  );
}
