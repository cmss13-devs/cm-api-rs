export const apiPath = import.meta.env.VITE_API_PATH || "/api";

/**
 * Attempt to refresh the session token
 */
const attemptRefresh = async (): Promise<boolean> => {
  try {
    const refreshRes = await fetch(`${apiPath}/auth/refresh`, {
      method: "POST",
      credentials: "include",
    });
    return refreshRes.ok;
  } catch {
    return false;
  }
};

/**
 * Redirect to login page, preserving current location
 */
const redirectToLogin = (): never => {
  const currentPath = window.location.pathname + window.location.search + window.location.hash;
  window.location.href = `${apiPath}/auth/login?redirect=${encodeURIComponent(currentPath)}`;
  throw new Error("Session expired - redirecting to login");
};

/**
 * Make an authenticated API call with automatic token refresh handling
 */
export const callApi = async (
  toCall: string,
  init?: RequestInit | undefined,
): Promise<Response> => {
  const response = await fetch(`${apiPath}${toCall}`, {
    ...init,
    credentials: "include",
  });

  if (response.status === 401) {
    // Attempt token refresh
    const refreshed = await attemptRefresh();

    if (refreshed) {
      // Retry original request
      return fetch(`${apiPath}${toCall}`, {
        ...init,
        credentials: "include",
      });
    }

    // Refresh failed, redirect to login
    redirectToLogin();
  }

  if (response.status === 403) {
    throw new Error("Access denied - insufficient permissions");
  }

  return response;
};
