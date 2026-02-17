import React, {
  type ReactElement,
  useContext,
  useEffect,
  useState,
} from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { callApi } from "../helpers/api";
import type {
  AuthentikUserFullResponse,
  AuthentikUserSearchResult,
} from "../types/authentik";
import { GlobalContext } from "../types/global";
import { LinkColor } from "./link";

export const AuthentikUserPage: React.FC = () => {
  const { uuid: urlUuid } = useParams<{ uuid: string }>();
  const navigate = useNavigate();

  const [searchQuery, setSearchQuery] = useState<string>("");
  const [userData, setUserData] = useState<AuthentikUserFullResponse | null>(
    null
  );
  const [searchResults, setSearchResults] = useState<
    AuthentikUserSearchResult[] | null
  >(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const global = useContext(GlobalContext);

  useEffect(() => {
    if (urlUuid) {
      setUserData(null);
      setSearchResults(null);
      setError(null);
      fetchUser(urlUuid);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [urlUuid]);

  const fetchUser = async (query: string) => {
    if (!query.trim()) {
      global?.updateAndShowToast("Please enter a search query");
      return;
    }

    setLoading(true);
    setError(null);
    setUserData(null);
    setSearchResults(null);

    const uuidResponse = await callApi(
      `/Authentik/UserByUuid/${encodeURIComponent(query.trim())}`
    );

    if (uuidResponse.status === 200) {
      const json = await uuidResponse.json();
      setUserData(json);
      setLoading(false);
      return;
    }

    if (uuidResponse.status === 404) {
      const searchResponse = await callApi(
        `/Authentik/SearchUsers?query=${encodeURIComponent(query.trim())}`
      );

      if (searchResponse.status === 200) {
        const results: AuthentikUserSearchResult[] =
          await searchResponse.json();
        if (results.length === 0) {
          setError("No users found matching that query");
        } else if (results.length === 1 && results[0].uuid) {
          navigate(`/authentik/${results[0].uuid}`, { replace: true });
          return;
        } else {
          setSearchResults(results);
        }
      } else {
        setError("Failed to search users");
      }
    } else {
      const json = await uuidResponse.json();
      setError(json.message || "Failed to fetch user");
    }

    setLoading(false);
  };

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      setUserData(null);
      setSearchResults(null);
      setError(null);
      navigate(`/authentik/${searchQuery.trim()}`);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="text-center text-2xl underline">
        Authentik User Lookup
      </div>

      <form
        className="flex flex-row justify-center gap-3"
        onSubmit={handleSearch}
      >
        <label htmlFor="authentik-search">Search:</label>
        <input
          type="text"
          id="authentik-search"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="UUID, username, or name"
          className="w-80"
        />
      </form>

      {loading && <div className="text-2xl text-center">Loading...</div>}
      {error && <div className="text-red-500 text-center">{error}</div>}

      {searchResults && searchResults.length > 0 && (
        <div className="flex flex-col gap-3">
          <div className="text-center text-gray-400">
            Multiple users found - select one:
          </div>
          <div className="flex flex-col gap-2">
            {searchResults.map((result) => (
              <Link
                key={result.pk}
                to={`/authentik/${result.uuid}`}
                className="border border-[#3f3f3f] p-3 rounded clicky flex flex-row justify-between items-center"
              >
                <div className="flex flex-col">
                  <span className="font-bold">{result.username}</span>
                  <span className="text-gray-400">{result.name}</span>
                </div>
                <span
                  className={
                    result.isActive ? "text-green-500" : "text-red-500"
                  }
                >
                  {result.isActive ? "Active" : "Inactive"}
                </span>
              </Link>
            ))}
          </div>
        </div>
      )}

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
  const [playerByCkey, setPlayerByCkey] = useState<string | null>(null);
  const [playerByUuid, setPlayerByUuid] = useState<string | null>(null);

  const ckey =
    typeof user.attributes.ckey === "string" ? user.attributes.ckey : null;

  useEffect(() => {
    if (ckey) {
      callApi(`/User?ckey=${encodeURIComponent(ckey)}`).then((response) => {
        if (response.status === 200) {
          setPlayerByCkey(ckey);
        } else {
          setPlayerByCkey(null);
        }
      });
    }

    if (user.uuid) {
      callApi(`/User?ckey=${encodeURIComponent(user.uuid)}`).then(
        (response) => {
          if (response.status === 200) {
            setPlayerByUuid(user.uuid);
          } else {
            setPlayerByUuid(null);
          }
        }
      );
    }
  }, [ckey, user.uuid]);

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

      {(playerByCkey || playerByUuid) && (
        <div className="flex flex-col gap-2">
          <div className="underline">Player Lookups:</div>
          <div className="pl-4 flex flex-row gap-4">
            {playerByCkey && (
              <Link
                to={`/user/${playerByCkey}`}
                className="text-blue-400 hover:underline"
              >
                By Ckey ({playerByCkey})
              </Link>
            )}
            {playerByUuid && (
              <Link
                to={`/user/${playerByUuid}`}
                className="text-blue-400 hover:underline"
              >
                By UUID
              </Link>
            )}
          </div>
        </div>
      )}

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
