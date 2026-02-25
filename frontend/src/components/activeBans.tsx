import type React from "react";
import { useEffect, useState } from "react";
import { callApi } from "../helpers/api";
import { Dialog } from "./dialog";

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
  const [searchInput, setSearchInput] = useState("");
  const [ckeyFilter, setCkeyFilter] = useState("");

  useEffect(() => {
    setLoading(true);
    const params = new URLSearchParams();
    params.set("page", page.toString());
    if (ckeyFilter) {
      params.set("ckey", ckeyFilter);
    }
    callApi(`/User/Banned?${params.toString()}`)
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
  }, [page, ckeyFilter]);

  const handleSearch = () => {
    setPage(0);
    setCkeyFilter(searchInput);
  };

  const handleClearSearch = () => {
    setSearchInput("");
    setCkeyFilter("");
    setPage(0);
  };

  if (!bans && loading) {
    return <div>Loading...</div>;
  }

  return (
    <div className="flex flex-col gap-3 min-w-0">
      <h1 className="text-2xl font-bold">View Active Bans</h1>

      <div className="flex flex-row flex-wrap gap-3 items-center">
        <input
          type="text"
          placeholder="Search by CKEY..."
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleSearch()}
          className="border border-[#3f3f3f] rounded p-2 bg-transparent flex-1 min-w-[150px]"
        />
        <button
          type="button"
          onClick={handleSearch}
          disabled={loading}
          className="border border-[#3f3f3f] rounded p-2 cursor-pointer disabled:opacity-50"
        >
          Search
        </button>
        {ckeyFilter && (
          <button
            type="button"
            onClick={handleClearSearch}
            className="border border-[#3f3f3f] rounded p-2 cursor-pointer text-gray-400 hover:text-white"
          >
            Clear
          </button>
        )}
      </div>

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
        <div className="overflow-x-auto">
          <table className="min-w-full">
            <thead>
              <tr>
                <th className="text-left p-2 whitespace-nowrap">CKEY</th>
                <th className="text-left p-2 whitespace-nowrap">Ban Type</th>
                <th className="text-left p-2 whitespace-nowrap">Reason</th>
                <th className="text-left p-2 whitespace-nowrap">Date</th>
                <th className="text-left p-2 whitespace-nowrap">Expires</th>
              </tr>
            </thead>
            <tbody>
              {bans.map((ban, idx) => (
                <BanRow key={`${ban.ckey}-${idx}`} ban={ban} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

// BYOND epoch is January 1, 2000
const BYOND_EPOCH = new Date(Date.UTC(2000, 0, 1, 0, 0, 0)).getTime();

const byondTimeToDate = (byondMinutes: number): Date => {
  return new Date(BYOND_EPOCH + byondMinutes * 60 * 1000);
};

const BanRow: React.FC<{ ban: BannedPlayer }> = ({ ban }) => {
  const [showReason, setShowReason] = useState(false);

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

  let expiresStr = "Never";
  if (!isPerma && ban.timeBanExpiration) {
    const expiresDate = byondTimeToDate(ban.timeBanExpiration);
    expiresStr = expiresDate.toLocaleString();
  }

  return (
    <>
      <tr className="border-t border-[#3f3f3f]">
        <td className="p-2">{ban.ckey || "Unknown"}</td>
        <td className={`p-2 ${isPerma ? "text-red-400" : "text-yellow-400"}`}>
          {banType}
        </td>
        <td
          className="p-2 max-w-md truncate cursor-pointer hover:text-blue-400"
          onClick={() => reason && setShowReason(true)}
          onKeyDown={(e) => e.key === "Enter" && reason && setShowReason(true)}
          tabIndex={reason ? 0 : undefined}
          role={reason ? "button" : undefined}
        >
          {reason || "No reason provided"}
        </td>
        <td className="p-2">{formattedDate}</td>
        <td className="p-2">{expiresStr}</td>
      </tr>
      <Dialog open={showReason} toggle={() => setShowReason(false)}>
        <div className="flex flex-col gap-4 mt-6">
          <h2 className="text-xl font-bold">
            Ban Reason for {ban.ckey || "Unknown"}
          </h2>
          <div className="whitespace-pre-wrap">{reason}</div>
        </div>
      </Dialog>
    </>
  );
};
