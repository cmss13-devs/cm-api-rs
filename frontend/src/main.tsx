import React from "react";
import ReactDOM from "react-dom/client";
import "./index.css";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import App from "./App";
import { AccountSettings } from "./components/accountSettings";
import { MyPlayerInfo } from "./components/myPlayerInfo";
import { ActiveBans } from "./components/activeBans";
import { AuthentikPanel } from "./components/authentikPanel";
import { AuthentikUserPage } from "./components/authentikUserPage";
import { BanHistory } from "./components/banHistory";
import { DiscordLookupPage } from "./components/discordLookupPage";
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
        handle: { title: "Home" },
      },
      {
        path: "/ticket/:round?/:ticketNum?",
        element: <Tickets />,
        handle: { title: "Tickets" },
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
        handle: { title: "Stickybans" },
      },
      {
        path: "/user/:ckey?",
        element: <LookupMenu />,
        handle: { title: "User Lookup" },
        loader: ({ params }) => {
          return params.ckey || "";
        },
      },
      {
        path: "/whitelists",
        element: <WhitelistMenu />,
        handle: { title: "Whitelists" },
      },
      {
        path: "/new_players",
        element: <NewPlayers />,
        handle: { title: "New Players" },
      },
      {
        path: "/user_manager",
        element: <AuthentikPanel />,
        handle: { title: "User Manager" },
      },
      {
        path: "/2fa",
        element: <TwoFactor />,
        handle: { title: "Two-Factor Auth" },
      },
      {
        path: "/bans",
        element: <ActiveBans />,
        handle: { title: "Active Bans" },
      },
      {
        path: "/ban-history",
        element: <BanHistory />,
        handle: { title: "Ban History" },
      },
      {
        path: "/authentik/:uuid?",
        element: <AuthentikUserPage />,
        handle: { title: "Authentik User" },
      },
      {
        path: "/discord-lookup/:discordId",
        element: <DiscordLookupPage />,
        handle: { title: "Discord Lookup" },
      },
      {
        path: "/account",
        element: <AccountSettings />,
        handle: { title: "Account Settings" },
      },
      {
        path: "/my-player-info",
        element: <MyPlayerInfo />,
        handle: { title: "My Player Info" },
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
