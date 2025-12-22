import React, { PropsWithChildren, useEffect, useState } from "react";
import { callApi } from "../helpers/api";

type RoundData = {
	mode: string;
	vote: number;
	ai: boolean;
	host?: string;
	round_id: number;
	players: number;
	revision: string;
	admins: number;
	gamestate: number;
	map_name: string;
	security_level: string;
	round_duration: number;
	time_dilation_current: number;
	time_dilation_avg: number;
	time_dilation_avg_slow: number;
	time_dilation_avg_fast: number;
	mcpu: number;
	cpu: number;
};

export const RoundData: React.FC = () => {
	const [roundData, setRoundData] = useState<RoundData | null>(null);

	const [errored, setErrored] = useState(false);

	useEffect(() => {
		if (!roundData) {
			callApi(`/Round`)
				.then((value) =>
					value
						.json()
						.then((json) => setRoundData(json.data))
						.catch(() => setErrored(true)),
				)
				.catch(() => setErrored(true));
		}
	}, [roundData, setRoundData]);

	if (errored) {
		return <div></div>;
	}

	if (!roundData) {
		return <div>Loading...</div>;
	}

	const formatGameState = (gameState: number) => {
		switch (gameState) {
			case 0:
				return "Starting";
			case 1:
				return "Lobby";
			case 2:
				return "Setting Up";
			case 3:
				return "Playing";
			case 4:
				return "Finished";
		}
		return "Unknown";
	};

	const formatDuration = (ms: number) => {
		if (ms < 0) ms = -ms;
		const time = {
			day: Math.floor(ms / 86400000),
			hour: Math.floor(ms / 3600000) % 24,
			minute: Math.floor(ms / 60000) % 60,
			second: Math.floor(ms / 1000) % 60,
		};
		return Object.entries(time)
			.filter((val) => val[1] !== 0)
			.map(([key, val]) => `${val} ${key}${val !== 1 ? "s" : ""}`)
			.join(", ");
	};

	return (
		<div className="flex flex-col justify-center mt-20 gap-2">
			<div className="flex flex-col md:flex-row justify-center gap-3">
				<InfoBox label="Round ID">{roundData.round_id}</InfoBox>
				<InfoBox label="Players">{roundData.players}</InfoBox>
				<InfoBox label="Admins">{roundData.admins}</InfoBox>
			</div>
			<div className="flex flex-col md:flex-row gap-3">
				<InfoBox label="Map Name">{roundData.map_name}</InfoBox>
				<InfoBox label="Game State">
					{formatGameState(roundData.gamestate)}
				</InfoBox>
			</div>
			<div className="flex flex-row gap-3">
				<InfoBox label="Duration">
					{formatDuration(roundData.round_duration * 100)}
				</InfoBox>
			</div>
		</div>
	);
};

interface InfoBoxProps extends PropsWithChildren {
	label: string;
}

const InfoBox = (props: InfoBoxProps) => {
	return (
		<div className="p-5 border-[#3f3f3f] border flex flex-col gap-2 grow rounded shadow-xl">
			<div className="text-3xl">{props.label}</div>
			{props.children}
		</div>
	);
};
