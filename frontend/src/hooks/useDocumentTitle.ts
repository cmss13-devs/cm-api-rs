import { useEffect } from "react";
import { type UIMatch, useMatches } from "react-router-dom";

interface RouteHandle {
  title?: string;
}

export function useDocumentTitle(suffix = "[cmdb]") {
  const matches = useMatches() as UIMatch<unknown, RouteHandle>[];

  useEffect(() => {
    // Find the last match with a title (most specific route)
    let title: string | undefined;
    for (const match of matches) {
      if (match.handle?.title) {
        title = match.handle.title;
      }
    }

    document.title = title ? `${title} | ${suffix}` : suffix;
  }, [matches, suffix]);
}
