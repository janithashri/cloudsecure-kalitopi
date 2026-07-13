import { useState } from "react";

export default function ConnectionTestButton({ onTest, testResult, disabled }) {
  const [loading, setLoading] = useState(false);

  const handleClick = async () => {
    setLoading(true);
    try {
      await onTest();
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-2">
      <button
        type="button"
        onClick={handleClick}
        disabled={disabled || loading}
        className={`rounded px-4 py-2 font-medium text-white disabled:opacity-50 ${
          testResult?.success
            ? "bg-green-600 hover:bg-green-500"
            : testResult?.success === false
            ? "bg-red-600 hover:bg-red-500"
            : "bg-slate-700 hover:bg-slate-600"
        }`}
      >
        {loading ? (
          <>
            <span className="mr-2 inline-block h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
            Testing...
          </>
        ) : testResult?.success ? (
          <>✓ Connection verified</>
        ) : testResult?.success === false ? (
          "Connection failed"
        ) : (
          "Test Connection"
        )}
      </button>
      {testResult?.success && (
        <p className="text-sm text-green-700">Connection verified. You can save and go to Providers.</p>
      )}
      {testResult?.success === false && testResult?.message && (
        <p className="text-sm text-red-600">{testResult.message}</p>
      )}
    </div>
  );
}
