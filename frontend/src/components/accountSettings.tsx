import type React from "react";
import { useContext, useEffect, useState } from "react";
import { callApi } from "../helpers/api";
import type {
  AuthentikError,
  AvailableOAuthSource,
  LinkedOAuthSource,
  UserProfileResponse,
} from "../types/authentik";
import { GlobalContext } from "../types/global";

export const AccountSettings: React.FC = () => {
  const global = useContext(GlobalContext);

  const [profile, setProfile] = useState<UserProfileResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [editingName, setEditingName] = useState(false);
  const [editingEmail, setEditingEmail] = useState(false);
  const [pendingName, setPendingName] = useState("");
  const [pendingEmail, setPendingEmail] = useState("");
  const [saving, setSaving] = useState(false);

  const fetchProfile = async () => {
    try {
      const response = await callApi("/Authentik/MyProfile");
      if (!response.ok) {
        const err: AuthentikError = await response.json();
        throw new Error(err.message || "Failed to fetch profile");
      }
      const data: UserProfileResponse = await response.json();
      setProfile(data);
      setPendingName(data.name);
      setPendingEmail(data.email || "");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load profile");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchProfile();
  }, []);

  const handleSaveName = async () => {
    if (!profile || pendingName === profile.name) {
      setEditingName(false);
      return;
    }

    setSaving(true);
    try {
      const response = await callApi("/Authentik/MyProfile", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: pendingName }),
      });

      if (!response.ok) {
        const err: AuthentikError = await response.json();
        throw new Error(err.message || "Failed to update name");
      }

      setProfile({ ...profile, name: pendingName });
      setEditingName(false);
      global?.updateAndShowToast("Display name updated");
    } catch (err) {
      global?.updateAndShowToast(
        err instanceof Error ? err.message : "Failed to update name"
      );
    } finally {
      setSaving(false);
    }
  };

  const handleSaveEmail = async () => {
    if (!profile || pendingEmail === (profile.email || "")) {
      setEditingEmail(false);
      return;
    }

    setSaving(true);
    try {
      const response = await callApi("/Authentik/MyProfile", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: pendingEmail }),
      });

      if (!response.ok) {
        const err: AuthentikError = await response.json();
        throw new Error(err.message || "Failed to update email");
      }

      setProfile({ ...profile, email: pendingEmail || null });
      setEditingEmail(false);
      global?.updateAndShowToast("Email updated");
    } catch (err) {
      global?.updateAndShowToast(
        err instanceof Error ? err.message : "Failed to update email"
      );
    } finally {
      setSaving(false);
    }
  };

  const handleUnlink = async (connectionPk: number, sourceName: string) => {
    try {
      const response = await callApi(
        `/Authentik/MyProfile/UnlinkSource/${connectionPk}`,
        { method: "DELETE" }
      );

      if (!response.ok) {
        const err: AuthentikError = await response.json();
        throw new Error(err.message || "Failed to unlink source");
      }

      global?.updateAndShowToast(`Unlinked ${sourceName}`);
      fetchProfile();
    } catch (err) {
      global?.updateAndShowToast(
        err instanceof Error ? err.message : "Failed to unlink source"
      );
    }
  };

  const handleCancelName = () => {
    setPendingName(profile?.name || "");
    setEditingName(false);
  };

  const handleCancelEmail = () => {
    setPendingEmail(profile?.email || "");
    setEditingEmail(false);
  };

  if (loading) {
    return <div>Loading...</div>;
  }

  if (error) {
    return <div className="text-red-400">Error: {error}</div>;
  }

  if (!profile) {
    return <div className="text-red-400">Profile not found</div>;
  }

  return (
    <div className="flex flex-col gap-6">
      <h1 className="text-xl font-bold">Account Settings</h1>

      <div className="flex flex-col gap-4">
        <h2 className="text-lg font-semibold">Profile Information</h2>

        <div className="flex flex-col gap-3">
          <div className="flex flex-row items-center gap-2">
            <span className="text-gray-400 w-32">Username:</span>
            <span>{profile.username}</span>
            <span className="text-gray-500 text-sm">(cannot be changed)</span>
          </div>

          <div className="flex flex-row items-center gap-2">
            <span className="text-gray-400 w-32">Display Name:</span>
            {editingName ? (
              <>
                <input
                  type="text"
                  value={pendingName}
                  onChange={(e) => setPendingName(e.target.value)}
                  disabled={saving}
                  className="bg-[#2a2a2a] border border-[#3f3f3f] rounded px-2 py-1 text-white flex-1 max-w-xs"
                  onKeyDown={(e) => {
                    if (e.key === "Enter") handleSaveName();
                    if (e.key === "Escape") handleCancelName();
                  }}
                />
                <button
                  type="button"
                  onClick={handleSaveName}
                  disabled={saving}
                  className="bg-green-600 hover:bg-green-700 disabled:bg-gray-600 px-3 py-1 rounded text-sm"
                >
                  {saving ? "Saving..." : "Save"}
                </button>
                <button
                  type="button"
                  onClick={handleCancelName}
                  disabled={saving}
                  className="bg-gray-600 hover:bg-gray-700 px-3 py-1 rounded text-sm"
                >
                  Cancel
                </button>
              </>
            ) : (
              <>
                <span>{profile.name}</span>
                <button
                  type="button"
                  onClick={() => setEditingName(true)}
                  className="text-blue-400 hover:text-blue-300 hover:underline text-sm"
                >
                  Edit
                </button>
              </>
            )}
          </div>

          <div className="flex flex-row items-center gap-2">
            <span className="text-gray-400 w-32">Email:</span>
            {editingEmail ? (
              <>
                <input
                  type="email"
                  value={pendingEmail}
                  onChange={(e) => setPendingEmail(e.target.value)}
                  disabled={saving}
                  className="bg-[#2a2a2a] border border-[#3f3f3f] rounded px-2 py-1 text-white flex-1 max-w-xs"
                  onKeyDown={(e) => {
                    if (e.key === "Enter") handleSaveEmail();
                    if (e.key === "Escape") handleCancelEmail();
                  }}
                />
                <button
                  type="button"
                  onClick={handleSaveEmail}
                  disabled={saving}
                  className="bg-green-600 hover:bg-green-700 disabled:bg-gray-600 px-3 py-1 rounded text-sm"
                >
                  {saving ? "Saving..." : "Save"}
                </button>
                <button
                  type="button"
                  onClick={handleCancelEmail}
                  disabled={saving}
                  className="bg-gray-600 hover:bg-gray-700 px-3 py-1 rounded text-sm"
                >
                  Cancel
                </button>
              </>
            ) : (
              <>
                <span className={profile.email ? "" : "text-gray-500"}>
                  {profile.email || "(not set)"}
                </span>
                <button
                  type="button"
                  onClick={() => setEditingEmail(true)}
                  className="text-blue-400 hover:text-blue-300 hover:underline text-sm"
                >
                  Edit
                </button>
              </>
            )}
          </div>
        </div>
      </div>

      <div className="flex flex-col gap-4">
        <h2 className="text-lg font-semibold">Linked Accounts</h2>

        {profile.linkedSources.length === 0 ? (
          <div className="text-gray-400">No linked accounts</div>
        ) : (
          <div className="flex flex-col gap-2">
            {profile.linkedSources.map((source) => (
              <LinkedSourceRow
                key={source.slug}
                source={source}
                onUnlink={() => handleUnlink(source.connectionPk, source.name)}
                authentikBaseUrl={profile.authentikBaseUrl}
              />
            ))}
          </div>
        )}

        {profile.availableSources.length > 0 && (
          <div className="flex flex-col gap-2 mt-4">
            <h3 className="text-md font-medium text-gray-400">
              Available to Link
            </h3>
            {profile.availableSources.map((source) => (
              <AvailableSourceRow
                key={source.slug}
                source={source}
                authentikBaseUrl={profile.authentikBaseUrl}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

const LinkedSourceRow: React.FC<{
  source: LinkedOAuthSource;
  onUnlink: () => void;
  authentikBaseUrl: string;
}> = ({ source, onUnlink, authentikBaseUrl }) => {
  const [unlinking, setUnlinking] = useState(false);

  const getExternalLink = (
    slug: string,
    parsedId: string | null
  ): string | null => {
    if (!parsedId) return null;
    switch (slug) {
      case "steam":
        return `https://steamcommunity.com/profiles/${parsedId}`;
      case "discord":
        return null;
      default:
        return null;
    }
  };

  const getDisplayId = (): string => {
    if (source.parsedId) return source.parsedId;

    if (source.identifier.startsWith("user:")) {
      return source.identifier.slice(5);
    }
    return source.identifier;
  };

  const handleUnlinkClick = async () => {
    setUnlinking(true);
    await onUnlink();
    setUnlinking(false);
  };

  const externalLink = getExternalLink(source.slug, source.parsedId);

  const iconUrl = source.icon ? `${authentikBaseUrl}${source.icon}` : null;

  return (
    <div className="flex flex-row items-center gap-3 py-2 border-b border-[#3f3f3f]">
      {iconUrl ? (
        <img src={iconUrl} alt={source.name} className="w-6 h-6" />
      ) : (
        <div className="w-6 h-6 bg-gray-600 rounded" />
      )}
      <span className="font-medium w-24">{source.name}</span>
      <span className="text-gray-300">{getDisplayId()}</span>
      {externalLink && (
        <a
          href={externalLink}
          target="_blank"
          rel="noopener noreferrer"
          className="text-blue-400 hover:text-blue-300 hover:underline text-sm"
        >
          View Profile
        </a>
      )}
      <button
        type="button"
        onClick={handleUnlinkClick}
        disabled={unlinking}
        className="ml-auto text-red-400 hover:text-red-300 hover:underline text-sm disabled:text-gray-500"
      >
        {unlinking ? "Unlinking..." : "Unlink"}
      </button>
    </div>
  );
};

const AvailableSourceRow: React.FC<{
  source: AvailableOAuthSource;
  authentikBaseUrl: string;
}> = ({ source, authentikBaseUrl }) => {
  const handleLink = () => {
    // Redirect to Authentik link-source flow
    window.location.href = `${authentikBaseUrl}/if/flow/link-source/?source=${source.slug}`;
  };

  const iconUrl = source.icon ? `${authentikBaseUrl}${source.icon}` : null;

  return (
    <div className="flex flex-row items-center gap-3 py-2 border-b border-[#3f3f3f]">
      {iconUrl ? (
        <img src={iconUrl} alt={source.name} className="w-6 h-6" />
      ) : (
        <div className="w-6 h-6 bg-gray-600 rounded" />
      )}
      <span className="font-medium w-24">{source.name}</span>
      <span className="text-gray-500">Not linked</span>
      <button
        type="button"
        onClick={handleLink}
        className="ml-auto text-green-400 hover:text-green-300 hover:underline text-sm"
      >
        Link
      </button>
    </div>
  );
};
