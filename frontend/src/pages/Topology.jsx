import { useState, useEffect, useRef } from 'react';
import { Network, ZoomIn, ZoomOut, RotateCcw, AlertTriangle, Monitor, Globe, Server, Activity, Filter } from 'lucide-react';
import { assetsAPI } from '../api/client';
import toast from 'react-hot-toast';

export default function TopologyPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [graphNodes, setGraphNodes] = useState([]);
  const [selectedNode, setSelectedNode] = useState(null);
  const [filterType, setFilterType] = useState('all'); // all, internal, external, compromised

  // Interactive Pan / Zoom State
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [panning, setPanning] = useState(false);
  const [panStart, setPanStart] = useState({ x: 0, y: 0 });
  
  // Dragging State
  const [draggedNodeId, setDraggedNodeId] = useState(null);

  const containerRef = useRef(null);

  useEffect(() => {
    assetsAPI.topology()
      .then((res) => {
        setData(res.data);
      })
      .catch(() => {
        toast.error('Failed to load network topology');
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  // Simple Force-Directed Layout Simulation
  useEffect(() => {
    if (!data || data.nodes.length === 0) return;

    const width = 900;
    const height = 550;

    // Initialize node positions
    let simNodes = data.nodes.map((n, idx) => {
      const angle = (idx / data.nodes.length) * 2 * Math.PI;
      const radius = n.type === 'internal' ? 140 : 240;
      return {
        ...n,
        x: width / 2 + radius * Math.cos(angle) + (Math.random() - 0.5) * 15,
        y: height / 2 + radius * Math.sin(angle) + (Math.random() - 0.5) * 15,
        vx: 0,
        vy: 0
      };
    });

    const edges = data.edges;
    let animId;
    let ticks = 0;

    const step = () => {
      const k = 160; // repulsion constant
      const c = 0.05; // spring constant
      const g = 0.015; // gravity constant
      const friction = 0.8;

      const centerX = width / 2;
      const centerY = height / 2;

      // 1. Repulsion between all nodes
      for (let i = 0; i < simNodes.length; i++) {
        for (let j = i + 1; j < simNodes.length; j++) {
          const n1 = simNodes[i];
          const n2 = simNodes[j];
          const dx = n2.x - n1.x || 0.1;
          const dy = n2.y - n1.y || 0.1;
          const distSq = dx * dx + dy * dy;
          const dist = Math.sqrt(distSq);

          if (dist < 350) {
            const force = k / (distSq + 12);
            const fx = (dx / dist) * force;
            const fy = (dy / dist) * force;

            n1.vx -= fx;
            n1.vy -= fy;
            n2.vx += fx;
            n2.vy += fy;
          }
        }
      }

      // 2. Attraction along edges
      edges.forEach((edge) => {
        const sourceNode = simNodes.find((n) => n.id === edge.source);
        const targetNode = simNodes.find((n) => n.id === edge.target);
        if (sourceNode && targetNode) {
          const dx = targetNode.x - sourceNode.x;
          const dy = targetNode.y - sourceNode.y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 0.1;

          const force = c * (dist - 140);
          const fx = (dx / dist) * force;
          const fy = (dy / dist) * force;

          sourceNode.vx += fx;
          sourceNode.vy += fy;
          targetNode.vx -= fx;
          targetNode.vy -= fy;
        }
      });

      // 3. Gravity & Update Positions
      simNodes.forEach((node) => {
        // Dragged node follows mouse directly, bypasses physics
        if (draggedNodeId === node.id) {
          node.vx = 0;
          node.vy = 0;
          return;
        }

        const dx = centerX - node.x;
        const dy = centerY - node.y;
        node.vx += dx * g;
        node.vy += dy * g;

        node.x += node.vx;
        node.y += node.vy;
        node.vx *= friction;
        node.vy *= friction;
      });

      setGraphNodes([...simNodes]);

      ticks++;
      if (ticks < 220) {
        animId = requestAnimationFrame(step);
      }
    };

    animId = requestAnimationFrame(step);
    return () => cancelAnimationFrame(animId);
  }, [data, draggedNodeId]);

  // Dragging event handlers
  const handleNodeMouseDown = (e, node) => {
    e.stopPropagation();
    setDraggedNodeId(node.id);
    setSelectedNode(node);
  };

  const handleGlobalMouseUp = () => {
    setDraggedNodeId(null);
    setPanning(false);
  };

  const handleMouseMove = (e) => {
    if (draggedNodeId && containerRef.current) {
      const rect = containerRef.current.getBoundingClientRect();
      const clientX = e.clientX - rect.left;
      const clientY = e.clientY - rect.top;

      // Convert client coords into SVG transform coordinate space
      const svgX = (clientX - pan.x) / zoom;
      const svgY = (clientY - pan.y) / zoom;

      setGraphNodes((prev) =>
        prev.map((n) => {
          if (n.id === draggedNodeId) {
            return { ...n, x: svgX, y: svgY };
          }
          return n;
        })
      );
    } else if (panning) {
      setPan((p) => ({
        x: p.x + e.clientX - panStart.x,
        y: p.y + e.clientY - panStart.y
      }));
      setPanStart({ x: e.clientX, y: e.clientY });
    }
  };

  const handleBgMouseDown = (e) => {
    setPanning(true);
    setPanStart({ x: e.clientX, y: e.clientY });
  };

  // Zoom control helpers
  const zoomIn = () => setZoom((z) => Math.min(2.5, z + 0.15));
  const zoomOut = () => setZoom((z) => Math.max(0.4, z - 0.15));
  const resetZoom = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };

  if (loading) {
    return <div className="page-loader"><div className="spinner" /></div>;
  }

  // Filter nodes & corresponding links
  const filteredNodes = graphNodes.filter((node) => {
    if (filterType === 'internal') return node.type === 'internal';
    if (filterType === 'external') return node.type === 'external';
    if (filterType === 'compromised') return node.status === 'compromised';
    return true;
  });

  const filteredNodeIds = new Set(filteredNodes.map((n) => n.id));

  const filteredEdges = (data?.edges || []).filter(
    (edge) => filteredNodeIds.has(edge.source) && filteredNodeIds.has(edge.target)
  );

  return (
    <div className="topology-container" onMouseUp={handleGlobalMouseUp}>
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 800 }}>Network Topology Map</h1>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 2 }}>
            Interactive flow map showing active device communication channels and security alert paths.
          </p>
        </div>
      </div>

      <div className="topology-layout-wrapper">
        {/* Left Side: Graph Area */}
        <div className="topology-graph-area">
          {/* Controls Overlay */}
          <div className="graph-controls-overlay">
            <button className="btn btn-ghost btn-sm btn-icon" onClick={zoomIn} title="Zoom In">
              <ZoomIn size={14} />
            </button>
            <button className="btn btn-ghost btn-sm btn-icon" onClick={zoomOut} title="Zoom Out">
              <ZoomOut size={14} />
            </button>
            <button className="btn btn-ghost btn-sm btn-icon" onClick={resetZoom} title="Reset View">
              <RotateCcw size={14} />
            </button>
            
            <div style={{ height: 18, width: 1, background: 'var(--border)', margin: '0 4px' }} />

            <div className="flex items-center gap-1">
              <Filter size={11} style={{ color: 'var(--text-secondary)' }} />
              <select 
                className="input" 
                style={{ width: 130, padding: '2px 8px', fontSize: 11, height: 'auto' }} 
                value={filterType} 
                onChange={(e) => setFilterType(e.target.value)}
              >
                <option value="all">All Assets</option>
                <option value="internal">Internal Only</option>
                <option value="external">External Only</option>
                <option value="compromised">Compromised</option>
              </select>
            </div>
          </div>

          {/* SVG canvas */}
          <div 
            ref={containerRef}
            className="graph-canvas-wrapper"
            onMouseDown={handleBgMouseDown}
            onMouseMove={handleMouseMove}
            style={{ cursor: panning ? 'grabbing' : 'grab' }}
          >
            <svg width="100%" height="100%" viewBox="0 0 900 550" preserveAspectRatio="xMidYMid slice">
              <defs>
                {/* Arrow markers for connection direction */}
                <marker id="arrow-info" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                  <path d="M 0 1 L 10 5 L 0 9 z" fill="#60a5fa" />
                </marker>
                <marker id="arrow-medium" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                  <path d="M 0 1 L 10 5 L 0 9 z" fill="var(--medium)" />
                </marker>
                <marker id="arrow-high" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                  <path d="M 0 1 L 10 5 L 0 9 z" fill="var(--high)" />
                </marker>
                <marker id="arrow-critical" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                  <path d="M 0 1 L 10 5 L 0 9 z" fill="var(--critical)" />
                </marker>
              </defs>

              <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
                {/* 1. Render Lines (Edges) */}
                {filteredEdges.map((edge, idx) => {
                  const src = filteredNodes.find((n) => n.id === edge.source);
                  const dst = filteredNodes.find((n) => n.id === edge.target);
                  if (!src || !dst) return null;

                  let markerId = "arrow-info";
                  let strokeColor = "rgba(96, 165, 250, 0.4)";
                  let strokeWidth = 1.5;
                  let lineClass = "";

                  if (edge.is_anomalous) {
                    markerId = `arrow-${edge.severity || 'critical'}`;
                    strokeColor = `var(--${edge.severity || 'critical'})`;
                    strokeWidth = 2.2;
                    lineClass = "edge-anomalous-flow";
                  }

                  return (
                    <g key={idx}>
                      <line
                        x1={src.x}
                        y1={src.y}
                        x2={dst.x}
                        y2={dst.y}
                        stroke={strokeColor}
                        strokeWidth={strokeWidth}
                        className={lineClass}
                        markerEnd={`url(#${markerId})`}
                      />
                      {/* Connection event count tag */}
                      {edge.count > 3 && (
                        <text
                          x={(src.x + dst.x) / 2}
                          y={(src.y + dst.y) / 2 - 4}
                          className="edge-label"
                        >
                          {edge.count}
                        </text>
                      )}
                    </g>
                  );
                })}

                {/* 2. Render Nodes */}
                {filteredNodes.map((node) => {
                  const isCompromised = node.status === 'compromised';
                  
                  let ringColor = "var(--border)";
                  let ringClass = "";
                  let fill = "var(--bg-card)";

                  if (isCompromised) {
                    ringColor = `var(--${node.severity || 'critical'})`;
                    ringClass = "node-compromised-ring";
                  } else if (node.type === 'internal') {
                    ringColor = "var(--accent-cyan)";
                  }

                  const isSelected = selectedNode?.id === node.id;

                  return (
                    <g
                      key={node.id}
                      transform={`translate(${node.x}, ${node.y})`}
                      onMouseDown={(e) => handleNodeMouseDown(e, node)}
                      className="topo-node"
                      style={{ cursor: 'pointer' }}
                    >
                      {/* Glowing outline if compromised or selected */}
                      {(isCompromised || isSelected) && (
                        <circle
                          r="25"
                          fill="none"
                          stroke={ringColor}
                          strokeWidth="3"
                          opacity={isSelected ? "0.9" : "0.5"}
                          className={ringClass}
                        />
                      )}

                      {/* Main Node Circle */}
                      <circle
                        r="18"
                        fill={fill}
                        stroke={isSelected ? "var(--text-primary)" : ringColor}
                        strokeWidth="2"
                      />

                      {/* Node Icon */}
                      <g className="node-icon-group" transform="translate(-6, -6)" style={{ pointerEvents: 'none' }}>
                        {node.type === 'internal' ? (
                          node.criticality === 'critical' ? (
                            <Server size={12} style={{ color: ringColor }} />
                          ) : (
                            <Monitor size={12} style={{ color: ringColor }} />
                          )
                        ) : (
                          <Globe size={12} style={{ color: 'var(--text-secondary)' }} />
                        )}
                      </g>

                      {/* Label */}
                      <text
                        y="30"
                        className="node-text"
                        style={{ fontWeight: isSelected ? '700' : '500' }}
                      >
                        {node.label}
                      </text>
                    </g>
                  );
                })}
              </g>
            </svg>
          </div>
        </div>

        {/* Right Side: Detail Panel */}
        <div className="topology-sidebar-area">
          {selectedNode ? (
            <div className="card flex-1" style={{ display: 'flex', flexDirection: 'column' }}>
              <div className="card-header flex justify-between" style={{ alignItems: 'center' }}>
                <span className="card-title">🔍 Asset Details</span>
                <span className={`badge ${selectedNode.type === 'internal' ? 'info' : 'secondary'}`}>
                  {selectedNode.type}
                </span>
              </div>
              <div className="card-body" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 14, overflowY: 'auto' }}>
                <div>
                  <div className="detail-label">Hostname / Name</div>
                  <div className="detail-value text-lg font-bold" style={{ color: 'var(--text-primary)' }}>
                    {selectedNode.label}
                  </div>
                </div>

                <div>
                  <div className="detail-label">IP Address</div>
                  <div className="detail-value font-mono">{selectedNode.id}</div>
                </div>

                <div className="flex gap-2">
                  <div className="flex-1">
                    <div className="detail-label">Criticality</div>
                    <span className={`badge ${selectedNode.criticality}`}>
                      {selectedNode.criticality}
                    </span>
                  </div>
                  <div className="flex-1">
                    <div className="detail-label">Platform</div>
                    <div className="detail-value text-xs font-semibold capitalize">
                      {selectedNode.os}
                    </div>
                  </div>
                </div>

                <div>
                  <div className="detail-label">Department / Scope</div>
                  <div className="detail-value text-xs">{selectedNode.department}</div>
                </div>

                <div style={{ height: 1, background: 'var(--border)', margin: '4px 0' }} />

                {/* Threat State info */}
                <div>
                  <div className="detail-label">Security Posture</div>
                  {selectedNode.status === 'compromised' ? (
                    <div className="threat-alert-panel">
                      <div className="flex gap-1.5 items-center font-bold" style={{ color: 'var(--critical)' }}>
                        <AlertTriangle size={13} /> Active Compromise
                      </div>
                      <div className="text-xs style-desc mt-1">
                        Recent threats flagged at this source. Check the alerts page immediately.
                      </div>
                    </div>
                  ) : (
                    <div className="threat-clear-panel">
                      🟢 Posture Secure (No Active Alerts)
                    </div>
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div className="card flex-1 flex items-center justify-center text-center p-6" style={{ background: 'rgba(15, 21, 32, 0.5)', borderStyle: 'dashed' }}>
              <div style={{ color: 'var(--text-muted)' }}>
                <Network size={36} style={{ margin: '0 auto 12px', opacity: 0.5 }} />
                <p style={{ fontSize: 13, fontWeight: 500 }}>Select a node in the map to inspect active connections and details.</p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Embedded CSS for styling graph elements */}
      <style>{`
        .topology-container {
          display: flex;
          flex-direction: column;
          height: calc(100vh - 120px);
        }
        .topology-layout-wrapper {
          display: flex;
          gap: 16px;
          height: calc(100vh - 180px);
          min-height: 460px;
        }
        .topology-graph-area {
          flex: 3;
          position: relative;
          display: flex;
          flex-direction: column;
        }
        .topology-sidebar-area {
          width: 280px;
          display: flex;
          flex-direction: column;
        }
        @media (max-width: 768px) {
          .topology-layout-wrapper {
            flex-direction: column-reverse;
            height: auto;
            min-height: auto;
          }
          .topology-graph-area {
            height: 450px;
            flex: none;
          }
          .topology-sidebar-area {
            width: 100%;
            flex: none;
          }
        }
        .graph-controls-overlay {
          position: absolute;
          top: 12px; left: 12px;
          display: flex;
          align-items: center;
          gap: 6px;
          background: rgba(19, 28, 46, 0.85);
          border: 1px solid var(--border);
          border-radius: var(--radius-md);
          padding: 4px;
          z-index: 10;
          backdrop-filter: blur(10px);
          box-shadow: var(--shadow-card);
        }
        .graph-canvas-wrapper {
          flex: 1;
          background: var(--bg-surface);
          border: 1px solid var(--border);
          border-radius: var(--radius-lg);
          overflow: hidden;
          box-shadow: inset 0 0 30px rgba(0, 0, 0, 0.4);
        }
        .node-text {
          fill: var(--text-secondary);
          font-size: 10px;
          text-anchor: middle;
          pointer-events: none;
        }
        .edge-label {
          fill: var(--text-muted);
          font-family: 'JetBrains Mono', monospace;
          font-size: 9px;
          text-anchor: middle;
          background: var(--bg-base);
          pointer-events: none;
        }
        .edge-anomalous-flow {
          stroke-dasharray: 6;
          animation: march 1.5s linear infinite;
        }
        @keyframes march {
          to { stroke-dashoffset: -12; }
        }
        .node-compromised-ring {
          animation: ringspin 3s linear infinite;
        }
        @keyframes ringspin {
          0% { stroke-dasharray: 1, 150; stroke-dashoffset: 0; }
          50% { stroke-dasharray: 90, 150; stroke-dashoffset: -35; }
          100% { stroke-dasharray: 90, 150; stroke-dashoffset: -124; }
        }
        .detail-label {
          font-size: 10px;
          color: var(--text-secondary);
          text-transform: uppercase;
          letter-spacing: 0.5px;
          margin-bottom: 2px;
        }
        .detail-value {
          color: var(--text-primary);
          font-weight: 500;
        }
        .threat-alert-panel {
          padding: 10px;
          background: rgba(255, 59, 92, 0.08);
          border: 1px solid var(--critical);
          border-radius: var(--radius-sm);
          margin-top: 6px;
        }
        .threat-clear-panel {
          padding: 8px 10px;
          background: rgba(16, 185, 129, 0.06);
          border: 1px solid var(--success);
          border-radius: var(--radius-sm);
          font-size: 11px;
          font-weight: 600;
          color: var(--success);
          margin-top: 6px;
        }
      `}</style>
    </div>
  );
}
