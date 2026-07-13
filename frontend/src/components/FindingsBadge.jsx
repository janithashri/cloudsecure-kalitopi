/**
 * Coloured pill for severity: CRITICAL=red, HIGH=orange, MEDIUM=yellow, LOW=grey, INFO=blue.
 */
export default function FindingsBadge({ severity, className = "" }) {
  const severityUpper = (severity || "").toUpperCase();
  const colors = {
    CRITICAL: "bg-red-600 text-white",
    HIGH: "bg-orange-500 text-white",
    MEDIUM: "bg-yellow-500 text-gray-900",
    LOW: "bg-gray-400 text-gray-900",
    INFO: "bg-blue-400 text-gray-900",
  };
  const style = colors[severityUpper] || "bg-gray-300 text-gray-700";
  return (
    <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${style} ${className}`}>
      {severity || "—"}
    </span>
  );
}
