import React, {
  type ReactElement,
  useContext,
  useEffect,
  useState,
} from "react";
import { useNavigate, useParams } from "react-router-dom";
import { callApi } from "../helpers/api";
import type { AuthentikUserFullResponse } from "../types/authentik";
import { GlobalContext } from "../types/global";
import { LinkColor } from "./link";

export const AuthentikUserPage: React.FC = () => {
  const { uuid: urlUuid } = useParams<{ uuid: string }>();
  const navigate = useNavigate();

  const [searchUuid, setSearchUuid] = useState<string>("");
  const [userData, setUserData] = useState<AuthentikUserFullResponse | null>(
    null
  );
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const global = useContext(GlobalContext);

  useEffect(() => {
    if (urlUuid && !userData && !loading) {
      fetchUser(urlUuid);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [urlUuid]);

  const fetchUser = (uuid: string) => {
    if (!uuid.trim()) {
      global?.updateAndShowToast("Please enter a UUID");
      return;
    }

    setLoading(true);
    setError(null);
    setUserData(null);

    callApi(`/Authentik/UserByUuid/${encodeURIComponent(uuid.trim())}`).then(
      (response) => {
        setLoading(false);
        if (response.status === 200) {
          response.json().then((json) => setUserData(json));
        } else if (response.status === 404) {
          setError("No user found with that UUID");
        } else {
          response.json().then((json) => {
            setError(json.message || "Failed to fetch user");
          });
        }
      }
    );
  };

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchUuid.trim()) {
      navigate(`/authentik/${searchUuid.trim()}`);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="text-center text-2xl underline">Authentik User Lookup</div>

      <form
        className="flex flex-row justify-center gap-3"
        onSubmit={handleSearch}
      >
        <label htmlFor="authentik-uuid">UUID:</label>
        <input
          type="text"
          id="authentik-uuid"
          value={searchUuid}
          onChange={(e) => setSearchUuid(e.target.value)}
          placeholder="Enter user UUID"
          className="w-80"
        />
      </form>

      {loading && <div className="text-2xl text-center">Loading...</div>}
      {error && <div className="text-red-500 text-center">{error}</div>}
      {userData && <AuthentikUserDetails user={userData} />}
    </div>
  );
};

const AuthentikUserDetails = ({
  user,
}: {
  user: AuthentikUserFullResponse;
}) => {
  const global = useContext(GlobalContext);

  const copyToClipboard = (value: string, label: string) => {
    navigator.clipboard.writeText(value);
    global?.updateAndShowToast(`Copied ${label} to clipboard`);
  };

  const formatAttributeValue = (value: unknown): string => {
    if (typeof value === "string") return value;
    if (typeof value === "number" || typeof value === "boolean")
      return String(value);
    return JSON.stringify(value);
  };

  const urlifyAttributeValue = (
    value: string,
    key: string
  ): ReactElement | string => {
    if (key === "steam_id")
      return (
        <LinkColor
          onClick={() =>
            window.open(
              `https://steamcommunity.com/profiles/${value}`,
              "_blank"
            )
          }
        >
          {value}
        </LinkColor>
      );
    return value;
  };

  return (
    <div className="flex flex-col gap-4 border border-[#3f3f3f] p-4 rounded">
      <div className="flex flex-col md:flex-row gap-6">
        <div className="flex flex-col gap-2">
          <div className="flex flex-row gap-2">
            <span className="underline">Username:</span>
            <span>{user.username}</span>
          </div>
          <div className="flex flex-row gap-2">
            <span className="underline">Name:</span>
            <span>{user.name}</span>
          </div>
          <div className="flex flex-row gap-2">
            <span className="underline">Active:</span>
            <span className={user.isActive ? "text-green-500" : "text-red-500"}>
              {user.isActive ? "Yes" : "No"}
            </span>
          </div>
          <div className="flex flex-row gap-2">
            <span className="underline">Last Login:</span>
            <span>{user.lastLogin ?? "Never"}</span>
          </div>
        </div>

        <div className="flex flex-col gap-2">
          <div className="flex flex-row gap-2">
            <span className="underline">UUID:</span>
            <LinkColor onClick={() => copyToClipboard(user.uuid ?? "", "UUID")}>
              {user.uuid ?? "N/A"}
            </LinkColor>
          </div>
          <div className="flex flex-row gap-2">
            <span className="underline">UID:</span>
            <LinkColor onClick={() => copyToClipboard(user.uid, "UID")}>
              {user.uid}
            </LinkColor>
          </div>
          <div className="flex flex-row gap-2">
            <span className="underline">PK:</span>
            <span>{user.pk}</span>
          </div>
        </div>
      </div>

      <div className="flex flex-col gap-2">
        <div className="underline">Groups:</div>
        <div className="pl-4">
          {user.groups.length > 0 ? user.groups.join(", ") : "None"}
        </div>
      </div>

      {Object.keys(user.attributes).length > 0 && (
        <div className="flex flex-col gap-2">
          <div className="underline">Attributes:</div>
          <div className="pl-4 flex flex-col gap-1">
            {Object.entries(user.attributes).map(([key, value]) => (
              <div key={key} className="flex flex-row gap-2">
                <span className="text-gray-400">{key}:</span>
                <span>
                  {urlifyAttributeValue(formatAttributeValue(value), key)}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
