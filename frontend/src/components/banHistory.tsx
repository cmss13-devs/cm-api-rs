import type React from "react";
import { useEffect, useState } from "react";
import { callApi } from "../helpers/api";
import { Dialog } from "./dialog";

interface HistoricalBan {
  ckey: string | null;
  text: string | null;
  date: string;
  banTime: number | null;
  roundId: number | null;
}

export const BanHistory: React.FC = () => {
  const [bans, setBans] = useState<HistoricalBan[]>();
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
    callApi(`/User/BanHistory?${params.toString()}`)
      .then((response) => response.json())
      .then((json: HistoricalBan[]) => {
        setBans(json);
      })
      .catch((err) => {
        console.error("Failed to fetch ban history:", err);
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
      <h1 className="text-2xl font-bold">Ban History</h1>

      <div className="text-gray-400 text-sm">
        This is a historical record of prior infractions. Bans listed here may no longer be active.
      </div>

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

      <div className="flex flex-row flex-wrap gap-3 items-center">
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
        {ckeyFilter && (
          <span className="text-gray-400">Filtering by: {ckeyFilter}</span>
        )}
      </div>

      {loading && <div className="text-gray-400">Loading...</div>}

      {!loading && bans && bans.length === 0 && (
        <div className="text-gray-400">
          {page === 0 ? "No ban history found." : "No more bans on this page."}
        </div>
      )}

      {!loading && bans && bans.length > 0 && (
        <div className="overflow-x-auto">
          <table className="min-w-full">
            <thead>
              <tr>
                <th className="text-left p-2 whitespace-nowrap">CKEY</th>
                <th className="text-left p-2 whitespace-nowrap">Date</th>
                <th className="text-left p-2 whitespace-nowrap">Duration</th>
                <th className="text-left p-2 whitespace-nowrap">Round</th>
                <th className="text-left p-2 whitespace-nowrap">Reason</th>
              </tr>
            </thead>
            <tbody>
              {bans.map((ban, idx) => (
                <BanHistoryRow key={`${ban.ckey}-${ban.date}-${idx}`} ban={ban} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

const parseDate = (dateStr: string): Date | null => {
  // Try standard format first: "2020-02-14 00:00:00"
  const standardDate = new Date(Date.parse(dateStr.replace(" ", "T")));
  if (!Number.isNaN(standardDate.getTime())) {
    return standardDate;
  }

  // Try human-readable format: "Wed, September 6th of 2017"
  // Remove day name, ordinal suffixes, and "of"
  const cleaned = dateStr
    .replace(/^[A-Za-z]+,\s*/, "") // Remove "Wed, "
    .replace(/(\d+)(st|nd|rd|th)/, "$1") // Remove ordinal suffix
    .replace(/\s+of\s+/, " "); // Remove "of"

  const parsed = new Date(Date.parse(cleaned));
  if (!Number.isNaN(parsed.getTime())) {
    return parsed;
  }

  return null;
};

const BanHistoryRow: React.FC<{ ban: HistoricalBan }> = ({ ban }) => {
  const [showReason, setShowReason] = useState(false);

  const isPermanent = ban.banTime === null || ban.banTime <= 0;

  let formattedDate = ban.date || "Unknown";
  const parsedDate = ban.date ? parseDate(ban.date) : null;
  if (parsedDate) {
    formattedDate = parsedDate.toLocaleString();
  }

  const formatDuration = (minutes: number | null): string => {
    if (minutes === null || minutes <= 0) return "Permanent";
    if (minutes < 60) return `${minutes}m`;
    if (minutes < 1440) return `${Math.floor(minutes / 60)}h`;
    return `${Math.floor(minutes / 1440)}d`;
  };

  return (
    <>
      <tr className="border-t border-[#3f3f3f]">
        <td className="p-2">{ban.ckey || "Unknown"}</td>
        <td className="p-2">{formattedDate}</td>
        <td className={`p-2 ${isPermanent ? "text-red-400" : "text-yellow-400"}`}>
          {formatDuration(ban.banTime)}
        </td>
        <td className="p-2">{ban.roundId ?? "N/A"}</td>
        <td
          className="p-2 max-w-md truncate cursor-pointer hover:text-blue-400"
          onClick={() => ban.text && setShowReason(true)}
          onKeyDown={(e) => e.key === "Enter" && ban.text && setShowReason(true)}
          tabIndex={ban.text ? 0 : undefined}
          role={ban.text ? "button" : undefined}
        >
          {ban.text || "No reason provided"}
        </td>
      </tr>
      <Dialog open={showReason} toggle={() => setShowReason(false)}>
        <div className="flex flex-col gap-4 mt-6">
          <h2 className="text-xl font-bold">
            Ban Reason for {ban.ckey || "Unknown"}
          </h2>
          <div className="text-gray-400 text-sm">
            {formattedDate} - {formatDuration(ban.banTime)}
            {ban.roundId && ` - Round ${ban.roundId}`}
          </div>
          <div className="whitespace-pre-wrap">{ban.text}</div>
        </div>
      </Dialog>
    </>
  );
};
