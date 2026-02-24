import type React from "react";
import { useContext, useEffect, useState } from "react";
import { callApi } from "../helpers/api";
import type {
  AuthentikError,
  AvailableOAuthSource,
  ConsentInfo,
  LinkedOAuthSource,
  MfaDeviceInfo,
  SessionInfo,
  UserProfileResponse,
  UserSettingsResponse,
} from "../types/authentik";
import { GlobalContext } from "../types/global";

type TabId = "profile" | "sessions" | "consents" | "mfa";

const tabs: { id: TabId; label: string }[] = [
  { id: "profile", label: "Profile" },
  { id: "sessions", label: "Sessions" },
  { id: "consents", label: "Consents" },
  { id: "mfa", label: "MFA Devices" },
];

export const AccountSettings: React.FC = () => {
  const global = useContext(GlobalContext);

  const [activeTab, setActiveTab] = useState<TabId>("profile");

  const [profile, setProfile] = useState<UserProfileResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [editingName, setEditingName] = useState(false);
  const [editingEmail, setEditingEmail] = useState(false);
  const [pendingName, setPendingName] = useState("");
  const [pendingEmail, setPendingEmail] = useState("");
  const [saving, setSaving] = useState(false);

  // User settings state (sessions, consents, MFA devices)
  const [settings, setSettings] = useState<UserSettingsResponse | null>(null);
  const [settingsLoading, setSettingsLoading] = useState(true);

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

  const fetchSettings = async () => {
    setSettingsLoading(true);
    try {
      const response = await callApi("/Authentik/MySettings");
      if (!response.ok) {
        const err: AuthentikError = await response.json();
        throw new Error(err.message || "Failed to fetch settings");
      }
      const data: UserSettingsResponse = await response.json();
      setSettings(data);
    } catch (err) {
      console.error("Failed to load settings:", err);
    } finally {
      setSettingsLoading(false);
    }
  };

  useEffect(() => {
    fetchProfile();
    fetchSettings();
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
      await fetchProfile();
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

  const handleDeleteSession = async (uuid: string) => {
    try {
      const response = await callApi(`/Authentik/MySettings/Session/${uuid}`, {
        method: "DELETE",
      });

      if (!response.ok) {
        const err: AuthentikError = await response.json();
        throw new Error(err.message || "Failed to delete session");
      }

      global?.updateAndShowToast("Session deleted");
      await fetchSettings();
    } catch (err) {
      global?.updateAndShowToast(
        err instanceof Error ? err.message : "Failed to delete session"
      );
    }
  };

  const handleRevokeConsent = async (pk: number, appName: string) => {
    try {
      const response = await callApi(`/Authentik/MySettings/Consent/${pk}`, {
        method: "DELETE",
      });

      if (!response.ok) {
        const err: AuthentikError = await response.json();
        throw new Error(err.message || "Failed to revoke consent");
      }

      global?.updateAndShowToast(`Revoked consent for ${appName}`);
      await fetchSettings();
    } catch (err) {
      global?.updateAndShowToast(
        err instanceof Error ? err.message : "Failed to revoke consent"
      );
    }
  };

  const handleDeleteMfaDevice = async (
    deviceType: string,
    pk: string,
    name: string
  ) => {
    try {
      const response = await callApi(
        `/Authentik/MySettings/MfaDevice/${deviceType}/${pk}`,
        { method: "DELETE" }
      );

      if (!response.ok) {
        const err: AuthentikError = await response.json();
        throw new Error(err.message || "Failed to delete MFA device");
      }

      global?.updateAndShowToast(`Deleted MFA device: ${name}`);
      await fetchSettings();
    } catch (err) {
      global?.updateAndShowToast(
        err instanceof Error ? err.message : "Failed to delete MFA device"
      );
    }
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
    <div className="flex flex-col gap-4">
      <h1 className="text-xl font-bold">Account Settings</h1>

      {/* Tab Bar */}
      <div className="flex flex-row border-b border-[#3f3f3f]">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === tab.id
                ? "border-blue-500 text-blue-400"
                : "border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-500"
            }`}
          >
            {tab.label}
            {tab.id === "sessions" && settings && (
              <span className="ml-1.5 text-xs text-gray-500">
                ({settings.sessions.length})
              </span>
            )}
            {tab.id === "consents" && settings && (
              <span className="ml-1.5 text-xs text-gray-500">
                ({settings.consents.length})
              </span>
            )}
            {tab.id === "mfa" && settings && (
              <span className="ml-1.5 text-xs text-gray-500">
                ({settings.mfaDevices.length})
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="pt-2">
        {activeTab === "profile" && (
          <ProfileTab
            profile={profile}
            editingName={editingName}
            editingEmail={editingEmail}
            pendingName={pendingName}
            pendingEmail={pendingEmail}
            saving={saving}
            setEditingName={setEditingName}
            setEditingEmail={setEditingEmail}
            setPendingName={setPendingName}
            setPendingEmail={setPendingEmail}
            handleSaveName={handleSaveName}
            handleSaveEmail={handleSaveEmail}
            handleCancelName={handleCancelName}
            handleCancelEmail={handleCancelEmail}
            handleUnlink={handleUnlink}
          />
        )}

        {activeTab === "sessions" && (
          <SessionsTab
            settings={settings}
            settingsLoading={settingsLoading}
            onDeleteSession={handleDeleteSession}
          />
        )}

        {activeTab === "consents" && (
          <ConsentsTab
            settings={settings}
            settingsLoading={settingsLoading}
            onRevokeConsent={handleRevokeConsent}
          />
        )}

        {activeTab === "mfa" && (
          <MfaTab
            settings={settings}
            settingsLoading={settingsLoading}
            onDeleteDevice={handleDeleteMfaDevice}
          />
        )}
      </div>
    </div>
  );
};

// Tab Content Components
const ProfileTab: React.FC<{
  profile: UserProfileResponse;
  editingName: boolean;
  editingEmail: boolean;
  pendingName: string;
  pendingEmail: string;
  saving: boolean;
  setEditingName: (v: boolean) => void;
  setEditingEmail: (v: boolean) => void;
  setPendingName: (v: string) => void;
  setPendingEmail: (v: string) => void;
  handleSaveName: () => void;
  handleSaveEmail: () => void;
  handleCancelName: () => void;
  handleCancelEmail: () => void;
  handleUnlink: (pk: number, name: string) => void;
}> = ({
  profile,
  editingName,
  editingEmail,
  pendingName,
  pendingEmail,
  saving,
  setEditingName,
  setEditingEmail,
  setPendingName,
  setPendingEmail,
  handleSaveName,
  handleSaveEmail,
  handleCancelName,
  handleCancelEmail,
  handleUnlink,
}) => (
  <div className="flex flex-col gap-6">
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

const SessionsTab: React.FC<{
  settings: UserSettingsResponse | null;
  settingsLoading: boolean;
  onDeleteSession: (uuid: string) => void;
}> = ({ settings, settingsLoading, onDeleteSession }) => (
  <div className="flex flex-col gap-4">
    <h2 className="text-lg font-semibold">Active Sessions</h2>

    {settingsLoading ? (
      <div className="text-gray-400">Loading sessions...</div>
    ) : settings?.sessions.length === 0 ? (
      <div className="text-gray-400">No active sessions</div>
    ) : (
      <div className="flex flex-col gap-2">
        {settings?.sessions.map((session) => (
          <SessionRow
            key={session.uuid}
            session={session}
            onDelete={() => onDeleteSession(session.uuid)}
          />
        ))}
      </div>
    )}
  </div>
);

const ConsentsTab: React.FC<{
  settings: UserSettingsResponse | null;
  settingsLoading: boolean;
  onRevokeConsent: (pk: number, appName: string) => void;
}> = ({ settings, settingsLoading, onRevokeConsent }) => (
  <div className="flex flex-col gap-4">
    <h2 className="text-lg font-semibold">Application Consents</h2>

    {settingsLoading ? (
      <div className="text-gray-400">Loading consents...</div>
    ) : settings?.consents.length === 0 ? (
      <div className="text-gray-400">No application consents</div>
    ) : (
      <div className="flex flex-col gap-2">
        {settings?.consents.map((consent) => (
          <ConsentRow
            key={consent.pk}
            consent={consent}
            onRevoke={() =>
              onRevokeConsent(consent.pk, consent.applicationName)
            }
          />
        ))}
      </div>
    )}
  </div>
);

const MfaTab: React.FC<{
  settings: UserSettingsResponse | null;
  settingsLoading: boolean;
  onDeleteDevice: (deviceType: string, pk: string, name: string) => void;
}> = ({ settings, settingsLoading, onDeleteDevice }) => (
  <div className="flex flex-col gap-4">
    <h2 className="text-lg font-semibold">MFA Devices</h2>

    {settingsLoading ? (
      <div className="text-gray-400">Loading MFA devices...</div>
    ) : settings?.mfaDevices.length === 0 ? (
      <div className="text-gray-400">No MFA devices configured</div>
    ) : (
      <div className="flex flex-col gap-2">
        {settings?.mfaDevices.map((device) => (
          <MfaDeviceRow
            key={`${device.deviceType}-${device.pk}`}
            device={device}
            onDelete={() =>
              onDeleteDevice(device.deviceType, device.pk, device.name)
            }
          />
        ))}
      </div>
    )}
  </div>
);

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

  const iconUrl = source.icon
    ? `${authentikBaseUrl}${source.icon}`
    : `${authentikBaseUrl}/static/authentik/sources/${source.slug}.svg`;

  return (
    <div className="flex flex-row items-center gap-3 py-2 border-b border-[#3f3f3f]">
      <img src={iconUrl} alt={source.name} className="w-6 h-6" />
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

  const iconUrl = source.icon
    ? `${authentikBaseUrl}${source.icon}`
    : `${authentikBaseUrl}/static/authentik/sources/${source.slug}.svg`;

  return (
    <div className="flex flex-row items-center gap-3 py-2 border-b border-[#3f3f3f]">
      <img src={iconUrl} alt={source.name} className="w-6 h-6" />
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

const SessionRow: React.FC<{
  session: SessionInfo;
  onDelete: () => void;
}> = ({ session, onDelete }) => {
  const [deleting, setDeleting] = useState(false);

  const handleDeleteClick = async () => {
    setDeleting(true);
    await onDelete();
    setDeleting(false);
  };

  const formatDate = (dateStr: string): string => {
    try {
      const date = new Date(dateStr);
      return date.toLocaleString();
    } catch {
      return dateStr;
    }
  };

  return (
    <div className="flex flex-row items-center gap-3 py-2 border-b border-[#3f3f3f]">
      <div className="flex flex-col flex-1">
        <div className="flex flex-row items-center gap-2">
          <span className="font-medium">{session.browser}</span>
          {session.current && (
            <span className="text-xs bg-green-600 px-2 py-0.5 rounded">
              Current
            </span>
          )}
        </div>
        <span className="text-sm text-gray-400">
          {session.os} - {session.device}
        </span>
        <span className="text-sm text-gray-500">
          Last used: {formatDate(session.lastUsed)} from {session.lastIp}
        </span>
      </div>
      {!session.current && (
        <button
          type="button"
          onClick={handleDeleteClick}
          disabled={deleting}
          className="text-red-400 hover:text-red-300 hover:underline text-sm disabled:text-gray-500"
        >
          {deleting ? "Deleting..." : "Delete"}
        </button>
      )}
    </div>
  );
};

const ConsentRow: React.FC<{
  consent: ConsentInfo;
  onRevoke: () => void;
}> = ({ consent, onRevoke }) => {
  const [revoking, setRevoking] = useState(false);

  const handleRevokeClick = async () => {
    setRevoking(true);
    await onRevoke();
    setRevoking(false);
  };

  const formatDate = (dateStr: string | null): string => {
    if (!dateStr) return "Never";
    try {
      const date = new Date(dateStr);
      return date.toLocaleString();
    } catch {
      return dateStr;
    }
  };

  return (
    <div className="flex flex-row items-center gap-3 py-2 border-b border-[#3f3f3f]">
      <div className="flex flex-col flex-1">
        <span className="font-medium">{consent.applicationName}</span>
        {consent.expires && (
          <span className="text-sm text-gray-500">
            Expires: {formatDate(consent.expires)}
          </span>
        )}
      </div>
      {consent.applicationUrl && (
        <a
          href={consent.applicationUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="text-blue-400 hover:text-blue-300 hover:underline text-sm"
        >
          Open
        </a>
      )}
      <button
        type="button"
        onClick={handleRevokeClick}
        disabled={revoking}
        className="text-red-400 hover:text-red-300 hover:underline text-sm disabled:text-gray-500"
      >
        {revoking ? "Revoking..." : "Revoke"}
      </button>
    </div>
  );
};

const MfaDeviceRow: React.FC<{
  device: MfaDeviceInfo;
  onDelete: () => void;
}> = ({ device, onDelete }) => {
  const [deleting, setDeleting] = useState(false);

  const handleDeleteClick = async () => {
    setDeleting(true);
    await onDelete();
    setDeleting(false);
  };

  const getDeviceTypeLabel = (type: string): string => {
    switch (type) {
      case "authentik_stages_authenticator_totp.totpdevice":
        return "Authenticator App (TOTP)";
      case "authentik_stages_authenticator_webauthn.webauthndevice":
        return "Security Key (WebAuthn)";
      case "authentik_stages_authenticator_static.staticdevice":
        return "Backup Codes";
      case "authentik_stages_authenticator_duo.duodevice":
        return "Duo";
      case "authentik_stages_authenticator_sms.smsdevice":
        return "SMS";
      default:
        return type;
    }
  };

  const formatDate = (dateStr: string | null): string => {
    if (!dateStr) return "";
    try {
      const date = new Date(dateStr);
      return date.toLocaleDateString();
    } catch {
      return dateStr;
    }
  };

  return (
    <div className="flex flex-row items-center gap-3 py-2 border-b border-[#3f3f3f]">
      <div className="flex flex-col flex-1">
        <span className="font-medium">{device.name}</span>
        <span className="text-sm text-gray-400">
          {getDeviceTypeLabel(device.deviceType)}
        </span>
        {device.created && (
          <span className="text-sm text-gray-500">
            Added: {formatDate(device.created)}
          </span>
        )}
        {device.lastUsed && (
          <span className="text-sm text-gray-500">
            Last used: {formatDate(device.lastUsed)}
          </span>
        )}
      </div>
      <button
        type="button"
        onClick={handleDeleteClick}
        disabled={deleting}
        className="text-red-400 hover:text-red-300 hover:underline text-sm disabled:text-gray-500"
      >
        {deleting ? "Deleting..." : "Delete"}
      </button>
    </div>
  );
};
