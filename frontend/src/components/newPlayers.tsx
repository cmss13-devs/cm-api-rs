import React, { useEffect, useState } from "react";
import { Player } from "./userLookup";
import { callApi } from "../helpers/api";
import { NameExpand } from "./nameExpand";
import { DetailedCid } from "./detailedCid";
import { DetailedIp } from "./detailedIp";

export const NewPlayers: React.FC = () => {
	const [newPlayers, setNewPlayers] = useState<Player[]>();
	const [searchedTime, setSearchedTime] = useState<number | undefined>();

	const [timeAgo, setTimeAgo] = useState(240);

	useEffect(() => {
		if (newPlayers && searchedTime === timeAgo) return;

		callApi(`/NewPlayers/${timeAgo}`).then((value) => {
			value.json().then((json: Player[]) => {
				setNewPlayers(json);
				setSearchedTime(timeAgo);
			});
		});
	}, [newPlayers, timeAgo, searchedTime]);

	if (!newPlayers) {
		return "Loading...";
	}

	return (
		<div className="flex flex-col gap-3">
			<div className="flex flex-row gap-3 justify-between">
				<div className="red-alert-bg p-2">
					<div className="foreground p-2">
						Indicates players that joined BYOND and this server within 24 hours
					</div>
				</div>
				<div className="flex flex-col justify-end">
					<div className="flex flex-row gap-3">
						<label>Joins since (minutes ago):</label>
						<input
							onKeyDown={(ev) => {
								if (ev.key === "Enter") {
									setTimeAgo(Number.parseInt(ev.currentTarget.value));
								}
							}}
							defaultValue={240}
							type="number"
						/>
					</div>
				</div>
			</div>
			<table>
				<thead>
					<tr>
						<th>CKEY</th>
						<th>Time Connected</th>
						<th>BYOND account age</th>
						<th>CID</th>
						<th>IP</th>
					</tr>
				</thead>
				<tbody>
					{newPlayers.map((player) => (
						<RenderNewPlayer player={player} key={player.ckey} />
					))}
				</tbody>
			</table>
		</div>
	);
};

const RenderNewPlayer = (props: { player: Player }) => {
	const { player } = props;

	const firstJoin = new Date(
		Date.parse(player.firstJoinDate!.replace(" ", "T")),
	);

	const byondAccountAge = new Date(Date.parse(player.byondAccountAge!));

	const isNew = firstJoin.getTime() - byondAccountAge.getTime() < 86400000;

	return (
		<tr>
			<td>
				<NameExpand name={player.ckey} />
			</td>
			<td className={isNew ? "red-alert-bg" : ""}>
				{firstJoin.toLocaleString()}
			</td>
			<td className={isNew ? "red-alert-bg" : ""}>
				{byondAccountAge.toLocaleDateString()}
			</td>
			<td>
				<DetailedCid cid={player.lastKnownCid} />
			</td>
			<td>
				<DetailedIp ip={player.lastKnownIp} />{" "}
			</td>
		</tr>
	);
};
