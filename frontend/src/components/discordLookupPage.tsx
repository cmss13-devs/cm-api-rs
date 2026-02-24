import type React from "react";
import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { callApi } from "../helpers/api";
import type { AuthentikUserFullResponse } from "../types/authentik";
import type { Player } from "./userLookup";

export const DiscordLookupPage: React.FC = () => {
	const { discordId } = useParams<{ discordId: string }>();

	const [gamePlayer, setGamePlayer] = useState<Player | null>(null);
	const [authentikUser, setAuthentikUser] =
		useState<AuthentikUserFullResponse | null>(null);
	const [gameLoading, setGameLoading] = useState(true);
	const [authentikLoading, setAuthentikLoading] = useState(true);
	const [gameError, setGameError] = useState<string | null>(null);
	const [authentikError, setAuthentikError] = useState<string | null>(null);

	useEffect(() => {
		if (!discordId) return;

		setGameLoading(true);
		setGameError(null);
		callApi(`/User?discord_id=${encodeURIComponent(discordId)}`)
			.then((response) => {
				if (response.status === 200) {
					response.json().then((json) => setGamePlayer(json));
				} else if (response.status === 404) {
					setGameError("No player found with this Discord ID");
				} else {
					setGameError("Failed to search game database");
				}
			})
			.catch(() => setGameError("Failed to search game database"))
			.finally(() => setGameLoading(false));

		setAuthentikLoading(true);
		setAuthentikError(null);
		callApi(`/Authentik/UserByDiscordId/${encodeURIComponent(discordId)}`)
			.then((response) => {
				if (response.status === 200) {
					response.json().then((json) => setAuthentikUser(json));
				} else if (response.status === 404) {
					setAuthentikError("No Authentik user found with this Discord ID");
				} else {
					setAuthentikError("Failed to search Authentik");
				}
			})
			.catch(() => setAuthentikError("Failed to search Authentik"))
			.finally(() => setAuthentikLoading(false));
	}, [discordId]);

	if (!discordId) {
		return (
			<div className="flex flex-col items-center gap-3">
				<div className="text-2xl">Discord Lookup</div>
				<div className="text-gray-400">No Discord ID provided</div>
			</div>
		);
	}

	const isLoading = gameLoading || authentikLoading;

	return (
		<div className="flex flex-col gap-6">
			<div className="text-center">
				<div className="text-2xl">Discord Lookup</div>
				<div className="text-gray-400">Discord ID: {discordId}</div>
			</div>

			{isLoading && <div className="text-center text-xl">Searching...</div>}

			{!isLoading && (
				<div className="flex flex-col md:flex-row gap-6 justify-center">
					<div className="flex flex-col gap-3 border border-[#3f3f3f] p-4 rounded min-w-[300px]">
						<div className="text-xl underline">Game Player</div>
						{gameLoading && <div className="text-gray-400">Loading...</div>}
						{gameError && <div className="text-gray-400">{gameError}</div>}
						{gamePlayer && (
							<div className="flex flex-col gap-2">
								<div className="flex flex-row gap-2">
									<span className="text-gray-400">Ckey:</span>
									<span>{gamePlayer.ckey}</span>
								</div>
								<div className="flex flex-row gap-2">
									<span className="text-gray-400">Last Login:</span>
									<span>{gamePlayer.lastLogin}</span>
								</div>
								{gamePlayer.isPermabanned && (
									<div className="text-red-500">PERMABANNED</div>
								)}
								{gamePlayer.isTimeBanned && (
									<div className="text-purple-500">TEMPBANNED</div>
								)}
								<Link
									to={`/user/${gamePlayer.ckey}`}
									className="mt-2 border border-[#555555] rounded p-2 text-center clicky"
								>
									View Full Profile
								</Link>
							</div>
						)}
					</div>

					<div className="flex flex-col gap-3 border border-[#3f3f3f] p-4 rounded min-w-[300px]">
						<div className="text-xl underline">Authentik User</div>
						{authentikLoading && (
							<div className="text-gray-400">Loading...</div>
						)}
						{authentikError && (
							<div className="text-gray-400">{authentikError}</div>
						)}
						{authentikUser && (
							<div className="flex flex-col gap-2">
								<div className="flex flex-row gap-2">
									<span className="text-gray-400">Username:</span>
									<span>{authentikUser.username}</span>
								</div>
								<div className="flex flex-row gap-2">
									<span className="text-gray-400">Name:</span>
									<span>{authentikUser.name}</span>
								</div>
								<div className="flex flex-row gap-2">
									<span className="text-gray-400">Active:</span>
									<span
										className={
											authentikUser.isActive ? "text-green-500" : "text-red-500"
										}
									>
										{authentikUser.isActive ? "Yes" : "No"}
									</span>
								</div>
								<div className="flex flex-row gap-2">
									<span className="text-gray-400">Groups:</span>
									<span>
										{authentikUser.groups.length > 0
											? authentikUser.groups.join(", ")
											: "None"}
									</span>
								</div>
								<Link
									to={`/authentik/${authentikUser.uuid}`}
									className="mt-2 border border-[#555555] rounded p-2 text-center clicky"
								>
									View Full Profile
								</Link>
							</div>
						)}
					</div>
				</div>
			)}

			{!isLoading && !gamePlayer && !authentikUser && (
				<div className="text-center text-gray-400">
					No results found for this Discord ID in either system.
				</div>
			)}
		</div>
	);
};
