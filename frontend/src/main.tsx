import React from "react";
import ReactDOM from "react-dom/client";
import "./index.css";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import App from "./App";
import { AuthentikPanel } from "./components/authentikPanel";
import HomePage from "./components/homePage";
import { NewPlayers } from "./components/newPlayers";
import { Stickybans } from "./components/stickybans";
import { Tickets } from "./components/tickets";
import { TwoFactor } from "./components/twoFactor";
import { LookupMenu } from "./components/userLookup";
import { WhitelistMenu } from "./components/whitelistPanel";

const router = createBrowserRouter([
  {
    path: "/",
    element: <App />,
    children: [
      {
        path: "",
        element: <HomePage />,
      },
      {
        path: "/ticket/:round?/:ticketNum?",
        element: <Tickets />,
        loader: ({ params }) => {
          return {
            round: params.round || "",
            ticketNum: params.ticketNum || "",
          };
        },
      },
      {
        path: "/sticky",
        element: <Stickybans />,
      },
      {
        path: "/user/:ckey?",
        element: <LookupMenu />,
        loader: ({ params }) => {
          return params.ckey || "";
        },
      },
      {
        path: "/whitelists",
        element: <WhitelistMenu />,
      },
      {
        path: "/new_players",
        element: <NewPlayers />,
      },
      {
        path: "/user_manager",
        element: <AuthentikPanel />,
      },
      {
        path: "/2fa",
        element: <TwoFactor />,
      },
    ],
  },
]);

// biome-ignore lint/style/noNonNullAssertion: this has to exist
ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <RouterProvider router={router} />
  </React.StrictMode>
);
