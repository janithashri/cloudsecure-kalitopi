import { useEffect, useMemo, useRef, useState } from "react";

const CARTOGRAPHY_NODE_COLORS = {
  AWSAccount: "#1F4E79",
  EC2Instance: "#2E7D32",
  AWSRole: "#4527A0",
  S3Bucket: "#E65100",
  RDSInstance: "#00695C",
  SecurityGroup: "#C62828",
  EC2SecurityGroup: "#C62828",
  AWSPolicy: "#F57F17",
  AWSVPC: "#37474F",
  AWSVpc: "#37474F",
  AWSUser: "#AD1457",
  KMSKey: "#558B2F",
};

const MAX_VISIBLE_NODES = 300;
const MIN_SCALE = 0.45;
const MAX_SCALE = 2.5;

function circleLayout(nodes, width, height) {
  if (!nodes.length) return {};
  const cx = width / 2;
  const cy = height / 2;
  const radius = Math.max(120, Math.min(width, height) / 2 - 80);
  const pos = {};
  nodes.forEach((n, i) => {
    const angle = (2 * Math.PI * i) / nodes.length;
    pos[n.id] = { x: cx + radius * Math.cos(angle), y: cy + radius * Math.sin(angle) };
  });
  return pos;
}

function shortNodeLabel(node) {
  const raw = String(
    node?.label ||
      node?.properties?.name ||
      node?.properties?.arn ||
      node?.properties?.id ||
      node?.id ||
      ""
  );
  if (!raw) return "Node";
  if (raw.startsWith("arn:")) {
    const section = raw.split("/").pop() || raw.split(":").pop() || raw;
    return section.slice(0, 26);
  }
  return raw.slice(0, 26);
}

function hashColor(key = "") {
  const palette = ["#0ea5e9", "#22c55e", "#a855f7", "#f59e0b", "#ef4444", "#14b8a6", "#f43f5e", "#84cc16"];
  let h = 0;
  for (let i = 0; i < key.length; i += 1) h = (h * 31 + key.charCodeAt(i)) >>> 0;
  return palette[h % palette.length];
}

function colorForNodeType(type) {
  return CARTOGRAPHY_NODE_COLORS[type] || hashColor(String(type || "Node"));
}

function forceLayout(nodes, edges, width, height) {
  if (!nodes.length) return {};
  const byId = new Map(nodes.map((n, i) => [n.id, i]));
  const pos = nodes.map((_, i) => ({
    x: width * (0.15 + ((i * 97) % 100) / 140),
    y: height * (0.15 + ((i * 57) % 100) / 140),
    vx: 0,
    vy: 0,
  }));

  const links = edges
    .map((e) => ({ s: byId.get(e.source), t: byId.get(e.target) }))
    .filter((e) => Number.isInteger(e.s) && Number.isInteger(e.t));

  const centerX = width / 2;
  const centerY = height / 2;
  const repulsion = 9800;
  const spring = 0.004;
  const targetLen = 240;
  const damping = 0.87;

  for (let step = 0; step < 220; step += 1) {
    for (let i = 0; i < pos.length; i += 1) {
      for (let j = i + 1; j < pos.length; j += 1) {
        const dx = pos[j].x - pos[i].x;
        const dy = pos[j].y - pos[i].y;
        const d2 = dx * dx + dy * dy + 0.01;
        const d = Math.sqrt(d2);
        const f = repulsion / d2;
        const fx = (f * dx) / d;
        const fy = (f * dy) / d;
        pos[i].vx -= fx;
        pos[i].vy -= fy;
        pos[j].vx += fx;
        pos[j].vy += fy;
      }
    }

    for (const l of links) {
      const a = pos[l.s];
      const b = pos[l.t];
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 1;
      const stretch = d - targetLen;
      const fx = spring * stretch * (dx / d);
      const fy = spring * stretch * (dy / d);
      a.vx += fx;
      a.vy += fy;
      b.vx -= fx;
      b.vy -= fy;
    }

    for (const p of pos) {
      p.vx += (centerX - p.x) * 0.0008;
      p.vy += (centerY - p.y) * 0.0008;
      p.vx *= damping;
      p.vy *= damping;
      p.x = Math.max(40, Math.min(width - 40, p.x + p.vx));
      p.y = Math.max(40, Math.min(height - 40, p.y + p.vy));
    }
  }

  // Final collision pass to keep nodes tappable/readable.
  const baseRadius = 26;
  const minGap = 30;
  for (let step = 0; step < 60; step += 1) {
    for (let i = 0; i < pos.length; i += 1) {
      for (let j = i + 1; j < pos.length; j += 1) {
        let dx = pos[j].x - pos[i].x;
        let dy = pos[j].y - pos[i].y;
        let d = Math.sqrt(dx * dx + dy * dy);

        // If perfectly overlapping, create a deterministic tiny nudge.
        if (d < 0.001) {
          const angle = ((i + 1) * (j + 3) * 17) % 360;
          dx = Math.cos((angle * Math.PI) / 180);
          dy = Math.sin((angle * Math.PI) / 180);
          d = 1;
        }

        const minDist = baseRadius * 2 + minGap;
        if (d < minDist) {
          const push = (minDist - d) * 0.5;
          const ux = dx / d;
          const uy = dy / d;
          pos[i].x = Math.max(40, Math.min(width - 40, pos[i].x - ux * push));
          pos[i].y = Math.max(40, Math.min(height - 40, pos[i].y - uy * push));
          pos[j].x = Math.max(40, Math.min(width - 40, pos[j].x + ux * push));
          pos[j].y = Math.max(40, Math.min(height - 40, pos[j].y + uy * push));
        }
      }
    }
  }

  const out = {};
  nodes.forEach((n, i) => {
    out[n.id] = { x: pos[i].x, y: pos[i].y };
  });
  return out;
}

export default function GraphCanvas({
  graphData,
  attackPathGraph,
  selectedAttack,
  onNodeClick,
  width = 900,
  height = 560,
}) {
  const svgRef = useRef(null);
  const dragRef = useRef(null);
  const nodeDragRef = useRef(null);
  const [viewport, setViewport] = useState({ scale: 1, tx: 0, ty: 0 });
  const [hoveredNode, setHoveredNode] = useState(null);
  const [showEdgeLabels, setShowEdgeLabels] = useState(false);
  const [manualNodePositions, setManualNodePositions] = useState({});

  const rawNodes = graphData?.nodes || [];
  const rawEdges = graphData?.edges || [];
  const nodes = rawNodes.slice(0, MAX_VISIBLE_NODES);
  const canvasWidth = useMemo(() => {
    const n = Math.max(1, nodes.length);
    return Math.max(width, Math.min(3200, Math.round(Math.sqrt(n) * 230)));
  }, [nodes.length, width]);
  const canvasHeight = useMemo(() => {
    const n = Math.max(1, nodes.length);
    return Math.max(height, Math.min(2400, Math.round(Math.sqrt(n) * 180)));
  }, [nodes.length, height]);
  const nodeIds = new Set(nodes.map((n) => n.id));
  const edges = rawEdges.filter((e) => nodeIds.has(e.source) && nodeIds.has(e.target));
  const pathNodeIds = new Set((attackPathGraph?.nodes || []).map((n) => n.id));
  const pathEdgeIds = new Set((attackPathGraph?.edges || []).map((e) => `${e.source}->${e.target}`));
  const hasPath = !!selectedAttack && (attackPathGraph?.violated || false);

  const positions = useMemo(() => {
    if (edges.length === 0) return circleLayout(nodes, canvasWidth, canvasHeight);
    return forceLayout(nodes, edges, canvasWidth, canvasHeight);
  }, [nodes, edges, canvasWidth, canvasHeight]);

  const effectivePositions = useMemo(() => {
    const merged = { ...positions };
    for (const [id, p] of Object.entries(manualNodePositions)) {
      if (merged[id]) merged[id] = p;
    }
    return merged;
  }, [positions, manualNodePositions]);

  const visibleTypes = useMemo(() => {
    const types = Array.from(new Set(nodes.map((n) => n.type).filter(Boolean)));
    return types.slice(0, 10);
  }, [nodes]);

  const relationshipColors = useMemo(() => {
    const map = {};
    for (const e of edges) {
      const rel = e.relationship || "RELATED_TO";
      if (!map[rel]) map[rel] = hashColor(rel);
    }
    return map;
  }, [edges]);

  const degreeByNodeId = useMemo(() => {
    const map = {};
    for (const n of nodes) map[n.id] = 0;
    for (const e of edges) {
      if (map[e.source] !== undefined) map[e.source] += 1;
      if (map[e.target] !== undefined) map[e.target] += 1;
    }
    return map;
  }, [nodes, edges]);

  function fitToGraph() {
    if (!nodes.length) {
      setViewport({ scale: 1, tx: 0, ty: 0 });
      return;
    }
    const pts = nodes.map((n) => effectivePositions[n.id]).filter(Boolean);
    if (!pts.length) return;
    let minX = pts[0].x;
    let maxX = pts[0].x;
    let minY = pts[0].y;
    let maxY = pts[0].y;
    for (const p of pts) {
      minX = Math.min(minX, p.x);
      maxX = Math.max(maxX, p.x);
      minY = Math.min(minY, p.y);
      maxY = Math.max(maxY, p.y);
    }
    const pad = 50;
    const graphW = Math.max(100, maxX - minX + pad * 2);
    const graphH = Math.max(100, maxY - minY + pad * 2);
    const scale = clampScale(Math.min(canvasWidth / graphW, canvasHeight / graphH));
    const cx = (minX + maxX) / 2;
    const cy = (minY + maxY) / 2;
    setViewport({
      scale,
      tx: canvasWidth / 2 - cx * scale,
      ty: canvasHeight / 2 - cy * scale,
    });
  }

  useEffect(() => {
    fitToGraph();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodes.length, edges.length, canvasWidth, canvasHeight]);

  useEffect(() => {
    setManualNodePositions((prev) => {
      const next = {};
      for (const n of nodes) {
        if (prev[n.id]) next[n.id] = prev[n.id];
      }
      return next;
    });
  }, [nodes]);

  function clampScale(value) {
    return Math.max(MIN_SCALE, Math.min(MAX_SCALE, value));
  }

  function onWheel(event) {
    event.preventDefault();
    const svg = svgRef.current;
    if (!svg) return;

    const rect = svg.getBoundingClientRect();
    const mx = event.clientX - rect.left;
    const my = event.clientY - rect.top;
    const zoomFactor = event.deltaY > 0 ? 0.9 : 1.1;

    setViewport((v) => {
      const nextScale = clampScale(v.scale * zoomFactor);
      const worldX = (mx - v.tx) / v.scale;
      const worldY = (my - v.ty) / v.scale;
      return {
        scale: nextScale,
        tx: mx - worldX * nextScale,
        ty: my - worldY * nextScale,
      };
    });
  }

  function onMouseDown(event) {
    if (nodeDragRef.current) return;
    dragRef.current = { x: event.clientX, y: event.clientY, tx: viewport.tx, ty: viewport.ty };
  }

  function onMouseMove(event) {
    if (nodeDragRef.current) {
      const svg = svgRef.current;
      if (!svg) return;
      const rect = svg.getBoundingClientRect();
      const mx = event.clientX - rect.left;
      const my = event.clientY - rect.top;
      const worldX = (mx - viewport.tx) / viewport.scale;
      const worldY = (my - viewport.ty) / viewport.scale;
      const { nodeId, offsetX, offsetY } = nodeDragRef.current;
      setManualNodePositions((prev) => ({
        ...prev,
        [nodeId]: { x: worldX - offsetX, y: worldY - offsetY },
      }));
      return;
    }
    if (!dragRef.current) return;
    const dx = event.clientX - dragRef.current.x;
    const dy = event.clientY - dragRef.current.y;
    setViewport((v) => ({ ...v, tx: dragRef.current.tx + dx, ty: dragRef.current.ty + dy }));
  }

  function onMouseUp() {
    dragRef.current = null;
    nodeDragRef.current = null;
  }

  function onNodeMouseDown(event, nodeId) {
    event.stopPropagation();
    const svg = svgRef.current;
    if (!svg) return;
    const rect = svg.getBoundingClientRect();
    const mx = event.clientX - rect.left;
    const my = event.clientY - rect.top;
    const worldX = (mx - viewport.tx) / viewport.scale;
    const worldY = (my - viewport.ty) / viewport.scale;
    const nodePos = effectivePositions[nodeId];
    if (!nodePos) return;
    nodeDragRef.current = {
      nodeId,
      offsetX: worldX - nodePos.x,
      offsetY: worldY - nodePos.y,
    };
  }

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-3">
      {hasPath && (
        <div className="mb-3 rounded-md border border-red-700/40 bg-red-900/20 px-3 py-2 text-sm text-red-300">
          Showing attack path: {selectedAttack}
        </div>
      )}
      {rawNodes.length > MAX_VISIBLE_NODES && (
        <div className="mb-3 rounded-md border border-amber-700/40 bg-amber-900/20 px-3 py-2 text-xs text-amber-300">
          Rendering first {MAX_VISIBLE_NODES} nodes out of {rawNodes.length} for performance. Use node-type filter to inspect specific resources.
        </div>
      )}
      <div className="mb-2 flex items-center gap-2 text-xs text-slate-300">
        <button
          onClick={() => setViewport((v) => ({ ...v, scale: clampScale(v.scale * 1.15) }))}
          className="rounded border border-slate-700 bg-slate-800 px-2 py-1 hover:bg-slate-700"
        >
          Zoom In
        </button>
        <button
          onClick={() => setViewport((v) => ({ ...v, scale: clampScale(v.scale * 0.85) }))}
          className="rounded border border-slate-700 bg-slate-800 px-2 py-1 hover:bg-slate-700"
        >
          Zoom Out
        </button>
        <button
          onClick={() => setViewport({ scale: 1, tx: 0, ty: 0 })}
          className="rounded border border-slate-700 bg-slate-800 px-2 py-1 hover:bg-slate-700"
        >
          Reset View
        </button>
        <button
          onClick={fitToGraph}
          className="rounded border border-slate-700 bg-slate-800 px-2 py-1 hover:bg-slate-700"
        >
          Fit to Graph
        </button>
        <label className="ml-2 inline-flex items-center gap-1 text-slate-400">
          <input
            type="checkbox"
            checked={showEdgeLabels}
            onChange={(e) => setShowEdgeLabels(e.target.checked)}
            className="h-3.5 w-3.5 accent-emerald-500"
          />
          Edge labels
        </label>
        <span className="ml-auto text-slate-400">
          Scroll to zoom, drag background to pan ({Math.round(viewport.scale * 100)}%)
        </span>
      </div>
      <div className="max-h-[70vh] overflow-auto rounded bg-slate-950">
      <svg
        ref={svgRef}
        width={canvasWidth}
        height={canvasHeight}
        viewBox={`0 0 ${canvasWidth} ${canvasHeight}`}
        className="rounded bg-slate-950"
        style={{ touchAction: "none" }}
        onWheel={onWheel}
        onMouseDown={onMouseDown}
        onMouseMove={onMouseMove}
        onMouseUp={onMouseUp}
        onMouseLeave={onMouseUp}
      >
        <defs>
          <marker id="arrow" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto">
            <path d="M0,0 L0,6 L9,3 z" fill="#64748b" />
          </marker>
          <marker id="arrow-red" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto">
            <path d="M0,0 L0,6 L9,3 z" fill="#ef4444" />
          </marker>
        </defs>
        <g
          transform={`translate(${viewport.tx}, ${viewport.ty}) scale(${viewport.scale})`}
          style={{ transition: dragRef.current ? "none" : "transform 120ms ease-out" }}
        >
          {edges.map((e, i) => {
            const s = effectivePositions[e.source];
            const t = effectivePositions[e.target];
            if (!s || !t) return null;
            const key = `${e.source}->${e.target}`;
            const inPath = pathEdgeIds.has(key);
            const dim = hasPath && !inPath;
            const edgeColor = inPath ? "#ef4444" : relationshipColors[e.relationship || "RELATED_TO"] || "#64748b";
            return (
              <g key={e.id || `${key}-${i}`}>
                <line
                  x1={s.x}
                  y1={s.y}
                  x2={t.x}
                  y2={t.y}
                  stroke={edgeColor}
                  strokeWidth={inPath ? 2.4 : 1.35}
                  opacity={dim ? 0.2 : 0.72}
                  strokeDasharray={inPath ? "7 5" : "0"}
                  markerEnd={`url(#${inPath ? "arrow-red" : "arrow"})`}
                >
                  {inPath && <animate attributeName="stroke-dashoffset" from="24" to="0" dur="1.2s" repeatCount="indefinite" />}
                </line>
                {showEdgeLabels && (
                  <text
                    x={(s.x + t.x) / 2}
                    y={(s.y + t.y) / 2}
                    textAnchor="middle"
                    fontSize="8"
                    fill="#94a3b8"
                    opacity={dim ? 0.25 : 0.7}
                  >
                    {e.relationship || "RELATED_TO"}
                  </text>
                )}
              </g>
            );
          })}

          {nodes.map((n) => {
            const p = effectivePositions[n.id];
            if (!p) return null;
            const inPath = pathNodeIds.has(n.id);
            const dim = hasPath && !inPath;
            const base = colorForNodeType(n.type);
            const fill = inPath ? "#dc2626" : base;
            const degree = degreeByNodeId[n.id] || 0;
            const radius = Math.max(16, Math.min(28, 18 + Math.min(10, degree)));
            const labelY = 16 + radius;
            return (
              <g
                key={n.id}
                transform={`translate(${p.x}, ${p.y})`}
                onClick={() => onNodeClick?.(n)}
                onMouseDown={(e) => onNodeMouseDown(e, n.id)}
                onMouseEnter={() => setHoveredNode(n)}
                onMouseLeave={() => setHoveredNode((prev) => (prev?.id === n.id ? null : prev))}
                className="cursor-pointer"
              >
                <circle
                  r={radius}
                  fill={fill}
                  opacity={dim ? 0.2 : 0.95}
                  stroke={inPath ? "#fca5a5" : "#cbd5e1"}
                  strokeWidth={inPath ? 2 : 1}
                />
                <text x="0" y={labelY} textAnchor="middle" fontSize="10" fill={dim ? "#64748b" : "#e2e8f0"}>
                  {shortNodeLabel(n)}
                </text>
              </g>
            );
          })}
        </g>
      </svg>
      </div>
      {hoveredNode && (
        <div className="mt-2 rounded border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-slate-300">
          <span className="font-semibold text-slate-100">{hoveredNode.type || "Node"}</span>
          {" - "}
          {hoveredNode.label || hoveredNode.id}
        </div>
      )}
      <div className="mt-3 flex flex-wrap gap-2">
        {visibleTypes.map((t) => (
          <span key={t} className="inline-flex items-center gap-1 rounded border border-slate-700 bg-slate-900 px-2 py-1 text-[10px] text-slate-300">
            <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ backgroundColor: colorForNodeType(t) }} />
            {t}
          </span>
        ))}
      </div>
    </div>
  );
}
