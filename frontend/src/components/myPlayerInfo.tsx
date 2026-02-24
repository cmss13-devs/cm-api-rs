import type React from "react";
import { useEffect, useState } from "react";
import { callApi } from "../helpers/api";
import type { AuthentikError, MyPlayerInfoResponse } from "../types/authentik";
import { JobBansList, NotesList } from "./userLookup";

export const MyPlayerInfo: React.FC = () => {
  const [playerInfo, setPlayerInfo] = useState<MyPlayerInfoResponse | null>(
    null
  );
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchPlayerInfo = async () => {
      try {
        const response = await callApi("/Authentik/MyPlayerInfo");
        if (!response.ok) {
          const err: AuthentikError = await response.json();
          throw new Error(err.message || "Failed to fetch player info");
        }
        const data: MyPlayerInfoResponse = await response.json();
        setPlayerInfo(data);
      } catch (err) {
        setError(
          err instanceof Error ? err.message : "Failed to load player info"
        );
      } finally {
        setLoading(false);
      }
    };

    fetchPlayerInfo();
  }, []);

  if (loading) {
    return <div>Loading...</div>;
  }

  if (error) {
    return <div className="text-red-400">Error: {error}</div>;
  }

  if (!playerInfo) {
    return <div className="text-red-400">Player info not found</div>;
  }

  return (
    <div className="flex flex-col gap-6">
      <h1 className="text-xl font-bold">My Player Info</h1>

      <div className="flex flex-col gap-2">
        <div className="flex flex-row items-center gap-2">
          <span className="text-gray-400 w-32">Ckey:</span>
          <span>{playerInfo.ckey}</span>
        </div>
        <div className="flex flex-row items-center gap-2">
          <span className="text-gray-400 w-32">Display Name:</span>
          <span>{playerInfo.displayName}</span>
        </div>
      </div>

      <div className="flex flex-col gap-4">
        <h2 className="text-lg font-semibold">
          Notes ({playerInfo.notes.length})
        </h2>
        <NotesList notes={playerInfo.notes} />
      </div>

      <div className="flex flex-col gap-4">
        <h2 className="text-lg font-semibold">
          Active Job Bans ({playerInfo.jobBans.length})
        </h2>
        <JobBansList jobBans={playerInfo.jobBans} />
      </div>
    </div>
  );
};
