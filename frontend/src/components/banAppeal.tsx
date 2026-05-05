import { useCallback, useContext, useEffect, useState } from "react";
import { callApi } from "../helpers/api";
import { GlobalContext } from "../types/global";

type ActiveBan = {
  banType: string;
  referenceId: string;
  reason: string;
  date: string | null;
  expiration: number | null;
  role: string | null;
  stickybanIdentifier: string | null;
  hasActiveAppeal: boolean;
  appealUrl: string | null;
};

type MyBansResponse = {
  ckey: string;
  bans: ActiveBan[];
};

const BAN_TYPE_LABELS: Record<string, string> = {
  permaban: "Permanent Ban",
  timeban: "Temporary Ban",
  stickyban: "Sticky Ban",
  jobban: "Job Ban",
  discord: "Discord Ban",
};

const BAN_TYPE_COLORS: Record<string, string> = {
  permaban: "bg-red-900/50 text-red-300 border-red-700",
  timeban: "bg-orange-900/50 text-orange-300 border-orange-700",
  stickyban: "bg-purple-900/50 text-purple-300 border-purple-700",
  jobban: "bg-yellow-900/50 text-yellow-300 border-yellow-700",
  discord: "bg-blue-900/50 text-blue-300 border-blue-700",
};

export function BanAppeal() {
  const global = useContext(GlobalContext);
  const [loading, setLoading] = useState(true);
  const [bansData, setBansData] = useState<MyBansResponse | null>(null);
  const [appealingBan, setAppealingBan] = useState<ActiveBan | null>(null);
  const [appealText, setAppealText] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const fetchBans = useCallback(async () => {
    setLoading(true);
    try {
      const response = await callApi("/Appeal/MyBans");
      if (!response.ok) {
        const err = await response.json();
        global?.updateAndShowToast(err.message || "Failed to load bans");
        return;
      }
      const data: MyBansResponse = await response.json();
      setBansData(data);
    } catch {
      global?.updateAndShowToast("Failed to load ban information");
    } finally {
      setLoading(false);
    }
  }, [global]);

  useEffect(() => {
    fetchBans();
  }, [fetchBans]);

  const handleSubmitAppeal = async () => {
    if (!appealingBan || !appealText.trim()) return;

    setSubmitting(true);
    try {
      const response = await callApi("/Appeal/Submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ban_type: appealingBan.banType,
          ban_reference_id: appealingBan.referenceId,
          appeal_reason: appealText.trim(),
        }),
      });

      if (!response.ok) {
        const err = await response.json();
        global?.updateAndShowToast(err.message || "Failed to submit appeal");
        return;
      }

      const result = await response.json();
      global?.updateAndShowToast("Appeal submitted successfully");
      setAppealingBan(null);
      setAppealText("");
      // Refresh the bans list
      await fetchBans();
      // Open the topic in a new tab
      window.open(result.topicUrl, "_blank");
    } catch {
      global?.updateAndShowToast("Failed to submit appeal");
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return (
      <div className="p-5 text-gray-400">Loading ban information...</div>
    );
  }

  if (!bansData || bansData.bans.length === 0) {
    return (
      <div className="p-5">
        <h2 className="text-xl text-gray-200 mb-3">Ban Appeal</h2>
        <p className="text-gray-400">You have no active bans to appeal.</p>
      </div>
    );
  }

  return (
    <div className="p-5 max-w-4xl mx-auto">
      <h2 className="text-xl text-gray-200 mb-1">Ban Appeal</h2>
      <p className="text-gray-500 text-sm mb-4">
        Appealing as: <span className="text-gray-300">{bansData.ckey}</span>
      </p>

      <div className="flex flex-col gap-3">
        {bansData.bans.map((ban) => (
          <div
            key={`${ban.banType}-${ban.referenceId}`}
            className="border border-gray-700 rounded p-4 bg-[#1e1e1e]"
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <span
                  className={`text-xs px-2 py-0.5 rounded border ${BAN_TYPE_COLORS[ban.banType] || "bg-gray-800 text-gray-300 border-gray-600"}`}
                >
                  {BAN_TYPE_LABELS[ban.banType] || ban.banType}
                </span>
                {ban.role && (
                  <span className="text-sm text-gray-400">({ban.role})</span>
                )}
                {ban.stickybanIdentifier && (
                  <span className="text-sm text-gray-400">
                    ({ban.stickybanIdentifier})
                  </span>
                )}
              </div>
              {ban.date && (
                <span className="text-xs text-gray-500">{ban.date}</span>
              )}
            </div>

            <p className="text-sm text-gray-300 mb-3">{ban.reason}</p>

            {ban.hasActiveAppeal ? (
              <a
                href={ban.appealUrl || "#"}
                target="_blank"
                rel="noopener noreferrer"
                className="text-sm text-blue-400 hover:text-blue-300 hover:underline"
              >
                Appeal Pending - View on Forum
              </a>
            ) : (
              <button
                type="button"
                onClick={() => {
                  setAppealingBan(ban);
                  setAppealText("");
                }}
                className="text-sm px-3 py-1 rounded border border-gray-500 text-gray-300 hover:text-white hover:border-gray-400"
              >
                Appeal
              </button>
            )}
          </div>
        ))}
      </div>

      {appealingBan && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-[#1e1e1e] border border-gray-700 rounded-lg p-6 w-full max-w-lg">
            <h3 className="text-lg text-gray-200 mb-1">Submit Appeal</h3>
            <p className="text-sm text-gray-500 mb-4">
              {BAN_TYPE_LABELS[appealingBan.banType] || appealingBan.banType}
              {appealingBan.role && ` (${appealingBan.role})`}
            </p>

            <div className="mb-2">
              <p className="text-xs text-gray-500 mb-1">Ban Reason:</p>
              <p className="text-sm text-gray-400 bg-[#2a2a2a] rounded p-2">
                {appealingBan.reason}
              </p>
            </div>

            <div className="mb-4">
              <label
                htmlFor="appeal-text"
                className="block text-sm text-gray-300 mb-1"
              >
                My Appeal
              </label>
              <textarea
                id="appeal-text"
                value={appealText}
                onChange={(e) => setAppealText(e.target.value)}
                placeholder="Explain why your ban should be reconsidered..."
                className="w-full h-40 bg-[#2a2a2a] border border-gray-600 rounded p-3 text-gray-200 text-sm resize-none focus:outline-none focus:border-gray-400"
                disabled={submitting}
              />
              <p className="text-xs text-gray-500 mt-1">
                This will be posted on the forum. Admins can already see all relevant context and the ban being appealed.
              </p>
            </div>

            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setAppealingBan(null)}
                disabled={submitting}
                className="px-4 py-2 text-sm rounded border border-gray-600 text-gray-400 hover:text-gray-200 hover:border-gray-400"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleSubmitAppeal}
                disabled={submitting || !appealText.trim()}
                className="px-4 py-2 text-sm rounded bg-blue-700 text-white hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {submitting ? "Submitting..." : "Submit Appeal"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
