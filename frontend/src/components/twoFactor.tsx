import type React from "react";
import { useContext, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { callApi } from "../helpers/api";
import { GlobalContext } from "../types/global";

export const TwoFactor: React.FC = () => {
  const [searchParams] = useSearchParams();
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const cid = searchParams.get("cid") || "";
  const ip = searchParams.get("ip") || "";

  const global = useContext(GlobalContext);

  const handleApprove = async () => {
    if (!cid || !ip) {
      setError("Both CID and IP are required");
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await callApi(
        `/TwoFactor?cid=${encodeURIComponent(cid)}&ip=${encodeURIComponent(ip)}`
      );
      const text = await response.text();
      setResult(text);
      global?.updateAndShowToast(text);
    } catch (err) {
      const message = err instanceof Error ? err.message : "An error occurred";
      setError(message);
      global?.updateAndShowToast(message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (cid && ip) {
      handleApprove();
    }
  }, []);

  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-2xl font-bold">Two-Factor Authentication Approval</h1>

      <div className="flex flex-col gap-2">
        <div className="flex flex-row gap-2">
          <span className="font-semibold">CID:</span>
          <span>{cid || "(not provided)"}</span>
        </div>
        <div className="flex flex-row gap-2">
          <span className="font-semibold">IP:</span>
          <span>{ip || "(not provided)"}</span>
        </div>
      </div>

      {!cid || !ip ? (
        <div className="text-yellow-400">
          Both CID and IP parameters are required. Please provide them in the
          URL query string (e.g., ?cid=123&ip=192.168.1.1).
        </div>
      ) : (
        <button
          type="button"
          onClick={handleApprove}
          disabled={loading}
          className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 text-white px-4 py-2 rounded w-fit"
        >
          {loading ? "Processing..." : "Approve 2FA Request"}
        </button>
      )}

      {result && (
        <div className="p-3 bg-green-900 rounded text-green-200">{result}</div>
      )}

      {error && (
        <div className="p-3 bg-red-900 rounded text-red-200">{error}</div>
      )}
    </div>
  );
};
