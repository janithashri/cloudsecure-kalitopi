import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from "recharts";

const COLORS = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#60a5fa",
  INFO: "#94a3b8",
};

export default function SeverityChart({ data }) {
  if (!data || Object.keys(data).length === 0) {
    return (
      <div className="flex h-48 items-center justify-center text-sm text-slate-500">
        No data available
      </div>
    );
  }

  const chartData = Object.entries(data)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }));

  if (!chartData.length) {
    return (
      <div className="flex h-48 items-center justify-center text-sm text-slate-500">
        No findings detected
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={200}>
      <PieChart>
        <Pie
          data={chartData}
          cx="50%"
          cy="50%"
          innerRadius={45}
          outerRadius={75}
          paddingAngle={3}
          dataKey="value"
        >
          {chartData.map((entry) => (
            <Cell key={entry.name} fill={COLORS[entry.name] || "#64748b"} />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{
            backgroundColor: "#1e293b",
            border: "1px solid #334155",
            borderRadius: "8px",
            color: "#e2e8f0",
            fontSize: "12px",
          }}
        />
        <Legend
          iconType="circle"
          iconSize={8}
          wrapperStyle={{ fontSize: "11px", color: "#94a3b8" }}
        />
      </PieChart>
    </ResponsiveContainer>
  );
}
