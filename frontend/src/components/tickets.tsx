import React, { useCallback, useContext, useEffect, useState } from "react";
import { callApi } from "../helpers/api";
import { Round } from "../types/rounds";
import { LinkColor } from "./link";
import { Ticket, TicketLoader } from "../types/ticket";
import { GlobalContext } from "../types/global";
import { Link, useLoaderData } from "react-router-dom";
import { TicketModal } from "./ticketmodal";

export const Tickets: React.FC = () => {
	const [lookupRound, setLookupRound] = useState<number | undefined>();

	const [acquiredData, setAcquiredData] = useState<Ticket[] | undefined>();

	const [loading, setLoading] = useState(false);

	const global = useContext(GlobalContext);

	const updateLookup = useCallback(
		(id?: number) => {
			const round = id || lookupRound;
			setLookupRound(round);
			if (!round) return;

			setLoading(true);

			callApi(`/Ticket/${round}`).then((value) => {
				if (value.status == 404) {
					global?.updateAndShowToast(
						"No tickets found for the provided round ID.",
					);
				} else {
					value.json().then((json) => {
						setAcquiredData(json);
					});
				}
				setLoading(false);
			});
		},
		[setLookupRound, setAcquiredData, global, lookupRound],
	);

	const { round } = useLoaderData() as TicketLoader;

	useEffect(() => {
		if (round && parseInt(round) != lookupRound) {
			setAcquiredData(undefined);
		}
		if (round && !acquiredData) {
			updateLookup(parseInt(round as string));
		}
	}, [lookupRound, round, acquiredData, updateLookup]);

	return (
		<div className="flex flex-col gap-3">
			<RecentRounds />
			<form
				className="flex flex-row justify-center gap-3"
				onSubmit={(event) => {
					event.preventDefault();
					updateLookup();
				}}
			>
				<label htmlFor="round">Round: </label>
				<input
					type="number"
					id="round"
					name="round"
					onInput={(event) => {
						const target = event.target as HTMLInputElement;
						setLookupRound(parseInt(target.value));
					}}
				></input>
			</form>
			{loading && (
				<div className="flex flex-row justify-center">Loading...</div>
			)}
			{acquiredData && (
				<TicketModal round={lookupRound} tickets={acquiredData} />
			)}
		</div>
	);
};

const RecentRounds = () => {
	const [rounds, setRecentRounds] = useState<Round[] | null>(null);

	useEffect(() => {
		if (!rounds) {
			callApi(`/Round/Recent`).then((value) =>
				value.json().then((json) => setRecentRounds(json)),
			);
		}
	});

	if (!rounds) {
		return <div className="flex flex-row justify-center">Loading...</div>;
	}

	return (
		<div className="flex flex-row justify-center gap-2">
			{rounds.map((round) => (
				<div key={round.id}>
					<LinkColor>
						<Link to={`/ticket/${round.id}`}>{round.id}</Link>
					</LinkColor>
				</div>
			))}
		</div>
	);
};
