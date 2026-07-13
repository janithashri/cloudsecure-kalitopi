import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";

const COLORS = { CIS: "#10b981", DPDP: "#06b6d4", RBI: "#8b5cf6", SBE: "#f59e0b" };

export default function FrameworkChart({ data }) {
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

  return (
    <ResponsiveContainer width="100%" height={200}>
      <BarChart data={chartData} margin={{ left: 10, right: 10, bottom: 5 }}>
        <XAxis dataKey="name" tick={{ fill: "#94a3b8", fontSize: 11 }} axisLine={false} tickLine={false} />
        <YAxis tick={{ fill: "#94a3b8", fontSize: 11 }} axisLine={false} tickLine={false} />
        <Tooltip
          contentStyle={{
            backgroundColor: "#1e293b",
            border: "1px solid #334155",
            borderRadius: "8px",
            color: "#e2e8f0",
            fontSize: "12px",
          }}
        />
        <Bar dataKey="value" radius={[4, 4, 0, 0]} barSize={40}>
          {chartData.map((entry) => (
            <Cell key={entry.name} fill={COLORS[entry.name] || "#64748b"} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
