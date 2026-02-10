import type React from "react";
import { useEffect, useState } from "react";
import { callApi } from "../helpers/api";

interface BannedPlayer {
  ckey: string | null;
  isTimeBanned: number | null;
  timeBanReason: string | null;
  timeBanDate: string | null;
  timeBanExpiration: number | null;
  isPermabanned: number | null;
  permabanReason: string | null;
  permabanDate: string | null;
}

export const ActiveBans: React.FC = () => {
  const [bans, setBans] = useState<BannedPlayer[]>();
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setLoading(true);
    callApi(`/User/Banned?page=${page}`)
      .then((response) => response.json())
      .then((json: BannedPlayer[]) => {
        setBans(json);
      })
      .catch((err) => {
        console.error("Failed to fetch bans:", err);
        setBans([]);
      })
      .finally(() => {
        setLoading(false);
      });
  }, [page]);

  if (!bans && loading) {
    return <div>Loading...</div>;
  }

  return (
    <div className="flex flex-col gap-3">
      <h1 className="text-2xl font-bold">View Active Bans</h1>

      <div className="flex flex-row gap-3 items-center">
        <button
          type="button"
          onClick={() => setPage((p) => Math.max(0, p - 1))}
          disabled={page === 0 || loading}
          className="border border-[#3f3f3f] rounded p-2 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Previous
        </button>
        <span>Page {page + 1}</span>
        <button
          type="button"
          onClick={() => setPage((p) => p + 1)}
          disabled={loading || (bans && bans.length < 20)}
          className="border border-[#3f3f3f] rounded p-2 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Next
        </button>
      </div>

      {loading && <div className="text-gray-400">Loading...</div>}

      {!loading && bans && bans.length === 0 && (
        <div className="text-gray-400">
          {page === 0 ? "No active bans found." : "No more bans on this page."}
        </div>
      )}

      {!loading && bans && bans.length > 0 && (
        <table>
          <thead>
            <tr>
              <th className="text-left p-2">CKEY</th>
              <th className="text-left p-2">Ban Type</th>
              <th className="text-left p-2">Reason</th>
              <th className="text-left p-2">Date</th>
            </tr>
          </thead>
          <tbody>
            {bans.map((ban, idx) => (
              <BanRow key={`${ban.ckey}-${idx}`} ban={ban} />
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
};

const BanRow: React.FC<{ ban: BannedPlayer }> = ({ ban }) => {
  const isPerma = ban.isPermabanned === 1;
  const banType = isPerma ? "Permaban" : "Timeban";
  const reason = isPerma ? ban.permabanReason : ban.timeBanReason;
  const dateStr = isPerma ? ban.permabanDate : ban.timeBanDate;

  let formattedDate = dateStr || "Unknown";
  if (dateStr) {
    try {
      const date = new Date(Date.parse(dateStr.replace(" ", "T")));
      formattedDate = date.toLocaleString();
    } catch {
      formattedDate = dateStr;
    }
  }

  return (
    <tr className="border-t border-[#3f3f3f]">
      <td className="p-2">{ban.ckey || "Unknown"}</td>
      <td className={`p-2 ${isPerma ? "text-red-400" : "text-yellow-400"}`}>
        {banType}
      </td>
      <td className="p-2 max-w-md truncate" title={reason || undefined}>
        {reason || "No reason provided"}
      </td>
      <td className="p-2">{formattedDate}</td>
    </tr>
  );
};
