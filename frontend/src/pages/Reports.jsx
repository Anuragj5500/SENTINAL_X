import { useState, useEffect } from 'react';
import { FileText, Download, Play, RefreshCw, Layers } from 'lucide-react';
import { reportsAPI } from '../api/client';
import toast from 'react-hot-toast';

export default function ReportsPage() {
  const [templates, setTemplates] = useState([]);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [selectedTemplate, setSelectedTemplate] = useState('');
  const [days, setDays] = useState(30);
  const [format, setFormat] = useState('json');
  const [customTitle, setCustomTitle] = useState('');
  const [reportData, setReportData] = useState(null);

  const load = async () => {
    setLoading(true);
    try {
      const tempRes = await reportsAPI.templates();
      setTemplates(tempRes.data);
      if (tempRes.data?.length > 0) {
        setSelectedTemplate(tempRes.data[0].id);
      }

      const histRes = await reportsAPI.list();
      setHistory(histRes.data);
    } catch {
      toast.error('Failed to load reports configuration');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const handleGenerate = async (e) => {
    e.preventDefault();
    setGenerating(true);
    setReportData(null);
    try {
      const payload = {
        report_type: selectedTemplate,
        format,
        days: parseInt(days),
        title: customTitle || undefined
      };

      if (format === 'csv') {
        const res = await reportsAPI.generate(payload);
        const blob = new Blob([res.data], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.setAttribute('download', `sentinelx_${selectedTemplate}_report.csv`);
        document.body.appendChild(link);
        link.click();
        link.remove();
        toast.success('CSV Report generated and downloaded!');
      } else {
        const res = await reportsAPI.generate(payload);
        setReportData(res.data);
        toast.success('JSON Report generated and loaded!');
      }
      load(); // Reload report history
    } catch {
      toast.error('Failed to generate report');
    } finally {
      setGenerating(false);
    }
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 800 }}>Reporting Center</h1>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 2 }}>
            Generate executive summaries, incident reports, and compliance matrices
          </p>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', marginBottom: 20 }}>
        {/* Generator Form */}
        <div style={{ flex: 1, minWidth: 320 }}>
          <div className="card">
            <div className="card-header"><span className="card-title"><Layers size={14} /> Report Generator</span></div>
            <div className="card-body">
              <form onSubmit={handleGenerate} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                <div className="input-group">
                  <label className="input-label">Report Template</label>
                  <select className="input" value={selectedTemplate}
                    onChange={(e) => setSelectedTemplate(e.target.value)}>
                    {templates.map((t) => (
                      <option key={t.id} value={t.id}>{t.name} — {t.description}</option>
                    ))}
                  </select>
                </div>

                <div className="grid-2">
                  <div className="input-group">
                    <label className="input-label">Timeframe (Days)</label>
                    <input className="input" type="number" min={1} max={90} value={days}
                      onChange={(e) => setDays(e.target.value)} required />
                  </div>
                  <div className="input-group">
                    <label className="input-label">Format</label>
                    <select className="input" value={format}
                      onChange={(e) => setFormat(e.target.value)}>
                      <option value="json">Interactive JSON Preview</option>
                      <option value="csv">Download CSV</option>
                    </select>
                  </div>
                </div>

                <div className="input-group">
                  <label className="input-label">Custom Title (Optional)</label>
                  <input className="input" placeholder="Q2 Security Executive Summary" value={customTitle}
                    onChange={(e) => setCustomTitle(e.target.value)} />
                </div>

                <button type="submit" className="btn btn-primary" style={{ justifyContent: 'center', marginTop: 6 }}
                  disabled={generating}>
                  {generating ? <div className="spinner" style={{ width: 14, height: 14 }} /> : <Play size={13} />}
                  {generating ? 'Generating...' : 'Generate Report'}
                </button>
              </form>
            </div>
          </div>
        </div>

        {/* History List */}
        <div style={{ width: 320 }}>
          <div className="card" style={{ height: '100%' }}>
            <div className="card-header"><span className="card-title">📜 Generation History</span></div>
            <div className="card-body" style={{ maxHeight: 280, overflowY: 'auto', padding: '12px 16px' }}>
              {history.map((h) => (
                <div key={h.id} style={{ padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontWeight: 700, fontSize: 12 }}>{h.title}</span>
                    <span className="badge resolved" style={{ fontSize: 9 }}>{h.status}</span>
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                    Type: <span style={{ textTransform: 'capitalize' }}>{h.report_type}</span> | {new Date(h.created_at).toLocaleString()}
                  </div>
                </div>
              ))}
              {history.length === 0 && <div className="text-sm text-muted">No reports generated yet</div>}
            </div>
          </div>
        </div>
      </div>

      {/* JSON Preview Panel */}
      {reportData && (
        <div className="card">
          <div className="card-header"><span className="card-title">📖 Report Preview</span></div>
          <div className="card-body">
            <pre style={{
              fontFamily: 'JetBrains Mono', fontSize: 12, background: 'var(--bg-base)',
              padding: 16, borderRadius: 'var(--radius-md)', border: '1px solid var(--border)',
              maxHeight: 400, overflow: 'auto', color: 'var(--text-secondary)'
            }}>
              {JSON.stringify(reportData, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
