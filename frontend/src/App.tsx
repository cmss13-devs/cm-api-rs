import type React from "react";
import { useCallback, useEffect, useState } from "react";
import { Link, Outlet, useSearchParams } from "react-router-dom";
import { LinkColor } from "./components/link";
import { NameExpand } from "./components/nameExpand";
import { apiPath } from "./helpers/api";
import { GlobalContext, type User } from "./types/global";

export default function App(): React.ReactElement {
  const [toastMessage, showToastMessage] = useState<string | null>();
  const [user, setUser] = useState<User | undefined>();
  const [authLoading, setAuthLoading] = useState(true);

  const [searchParams, setSearchParams] = useSearchParams();

  const displayToast = useCallback((string: string) => {
    showToastMessage(string);
    setTimeout(() => {
      showToastMessage("");
    }, 3000);
  }, []);

  const handleLogout = async () => {
    try {
      window.location.href = `${apiPath}/auth/logout`;
    } catch (error) {
      console.error("Logout failed:", error);
      displayToast("Logout failed. Please try again.");
    }
  };

  useEffect(() => {
    if (!user) {
      // In development with VITE_FAKE_USER, use fake user
      if (import.meta.env.VITE_FAKE_USER) {
        setUser({
          username: "debug",
          ckey: "debug",
          email: "debug@debug.debug",
          groups: ["admin"],
          manageable: ["mentor"],
        });
        setAuthLoading(false);
        return;
      }

      // Fetch user info from backend
      fetch(`${apiPath}/auth/userinfo`, {
        credentials: "include",
      })
        .then((response) => {
          if (response.status === 401) {
            // Not authenticated, redirect to login
            const currentPath = window.location.pathname + window.location.hash;
            window.location.href = `/api/auth/login?redirect=${encodeURIComponent(
              currentPath,
            )}`;
            return null;
          }
          if (!response.ok) {
            throw new Error("Failed to fetch user info");
          }
          return response.json();
        })
        .then((json) => {
          if (json) {
            setUser(json);
          }
        })
        .catch((error) => {
          console.error("Auth error:", error);
          // Redirect to login on error
          window.location.href = "/api/auth/login";
          setAuthLoading(false);
          return;
        });

      // Fetch allowed groups from backend
      fetch(`${apiPath}/Authentik/AllowedGroups`, {
        credentials: "include",
      })
        .then((response) => {
          if (!response.ok) {
            throw new Error("Failed to fetch allowed groups");
          }
          return response.json();
        })
        .then((json: { manageable: string[] }) => {
          setUser((exitingUser) => {
            if (exitingUser) {
              return {
                ...exitingUser,
                manageable: json.manageable,
              };
            }
          });
        })
        .catch((error) => {
          console.error("Auth error:", error);
        })
        .finally(() => {
          setAuthLoading(false);
        });
    } else {
      setAuthLoading(false);
    }
  }, [user]);

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const existing = params.get("existing");

    if (!existing) return;

    location.replace(`${location.origin}/#${existing}?forceRefresh=true`);
  }, []);

  useEffect(() => {
    if (searchParams.get("forceRefresh")) {
      displayToast("Session reloaded as you were timed out.");
      setSearchParams({});
    }
  }, [searchParams, setSearchParams, displayToast]);

  // Show loading state while checking authentication
  if (authLoading) {
    return (
      <div className="w-full h-screen flex items-center justify-center foreground">
        <div>Loading...</div>
      </div>
    );
  }

  return (
    <GlobalContext.Provider
      value={{ updateAndShowToast: displayToast, user: user }}
    >
      <div className="w-full foreground p-3 flex flex-row gap-2">
        <LinkColor>
          <Link to="/" className="underline">
            [cmdb]
          </Link>
        </LinkColor>
        |
        <LinkColor>
          <Link to="/sticky">Sticky Menu</Link>
        </LinkColor>
        |
        <LinkColor>
          <Link to="/ticket">Tickets</Link>
        </LinkColor>
        |
        <LinkColor>
          <Link to="/user">Users</Link>
        </LinkColor>
        |
        <LinkColor>
          <Link to="/whitelists">Whitelists</Link>
        </LinkColor>
        |
        <LinkColor>
          <Link to="/new_players">New Players</Link>
        </LinkColor>
        {user?.manageable?.length && (
          <>
            |
            <LinkColor>
              <Link to="/user_manager">User Manager</Link>
            </LinkColor>
          </>
        )}
        {user && (
          <>
            <span className="ml-auto text-gray-400">
              {user.username} (<NameExpand name={user.ckey}></NameExpand>)
            </span>
            <button
              type="button"
              onClick={handleLogout}
              className="text-red-400 hover:text-red-300 hover:underline"
            >
              Logout
            </button>
          </>
        )}
      </div>
      <div className="w-full md:container md:mx-auto flex flex-col foreground rounded mt-5 p-5">
        <Outlet />
      </div>
      <div className={`toast ${toastMessage ? "show" : ""}`}>
        {toastMessage}
      </div>
    </GlobalContext.Provider>
  );
}
