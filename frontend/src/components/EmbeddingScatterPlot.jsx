export default function EmbeddingScatterPlot({ points, title = "Principal Embeddings" }) {
  if (!points?.length) {
    return (
      <div className="flex h-80 items-center justify-center rounded-xl border border-slate-800 bg-slate-900 text-slate-500">
        No embedding data for this window.
      </div>
    );
  }

  const xs = points.map((p) => p.x);
  const ys = points.map((p) => p.y);
  const minX = Math.min(...xs);
  const maxX = Math.max(...xs);
  const minY = Math.min(...ys);
  const maxY = Math.max(...ys);
  const pad = 0.1;

  const scaleX = (x) => {
    const range = maxX - minX || 1;
    return ((x - minX) / range) * (100 - 2 * pad * 100) + pad * 100;
  };
  const scaleY = (y) => {
    const range = maxY - minY || 1;
    return 100 - (((y - minY) / range) * (100 - 2 * pad * 100) + pad * 100);
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
      <h3 className="mb-3 text-sm font-semibold text-white">{title}</h3>
      <div className="relative h-80 w-full overflow-hidden rounded-lg bg-slate-950">
        <svg viewBox="0 0 100 100" className="h-full w-full">
          {points.map((point) => (
            <circle
              key={point.principal_arn}
              cx={scaleX(point.x)}
              cy={scaleY(point.y)}
              r="1.8"
              fill={point.is_attack ? "#ef4444" : "#3b82f6"}
              opacity="0.85"
            >
              <title>
                {point.principal_arn}
                {point.attack_type ? ` (${point.attack_type})` : ""}
              </title>
            </circle>
          ))}
        </svg>
        <div className="absolute bottom-2 left-2 flex gap-3 text-xs text-slate-400">
          <span className="flex items-center gap-1">
            <span className="inline-block h-2 w-2 rounded-full bg-blue-500" /> Normal
          </span>
          <span className="flex items-center gap-1">
            <span className="inline-block h-2 w-2 rounded-full bg-red-500" /> Attack
          </span>
        </div>
      </div>
    </div>
  );
}
