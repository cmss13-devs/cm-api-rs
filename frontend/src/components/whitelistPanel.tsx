import React, { useEffect, useState } from "react";
import { callApi } from "../helpers/api";
import { NameExpand } from "./nameExpand";
import { LinkColor } from "./link";
import { Dialog } from "./dialog";

type WhitelistPlayer = {
	id: number;
	ckey: string;
	whitelistStatus: string;
};

type Filter = {
	[index: string]: boolean | undefined;
};

export const WhitelistMenu: React.FC = () => {
	const [whitelistees, setWhitelistees] = useState<
		WhitelistPlayer[] | undefined
	>();

	const [categories, setCategories] = useState<string[]>([]);

	const [viewFilters, setViewFilters] = useState(false);
	const [filter, setFilter] = useState<Filter>({});

	useEffect(() => {
		if (whitelistees) return;

		callApi("/Whitelist").then((value) =>
			value.json().then((json: WhitelistPlayer[]) => {
				setWhitelistees(json);

				json.forEach((whitelistee) => {
					whitelistee.whitelistStatus.split("|").forEach((status) => {
						setCategories((categories) =>
							categories.includes(status)
								? categories
								: [...categories, status],
						);
					});
				});
			}),
		);
	}, [whitelistees]);

	useEffect(() => {
		const obj: Filter = {};
		categories.forEach((category) => {
			obj[category] = true;
		});
		setFilter(obj);
	}, [categories]);

	const clearFilters = () => {
		const obj: Filter = {};
		categories.forEach((category) => {
			obj[category] = false;
		});
		setFilter(obj);
	};

	if (!whitelistees) {
		return "Loading...";
	}

	const filteredWhitelistees = whitelistees.filter((whitelistee) => {
		const whitelists = whitelistee.whitelistStatus.split("|");

		let filtered = true;

		whitelists.forEach((whitelist) => {
			if (filter[whitelist] == true) {
				filtered = false;
			}
		});

		if (filtered) return false;

		return true;
	});

	return (
		<div className="flex flex-col gap-3">
			<div className="flex flex-row gap-2 flex-wrap">
				<LinkColor onClick={() => setViewFilters(true)}>Set Filters</LinkColor>
				{viewFilters && (
					<Dialog open={viewFilters} toggle={() => setViewFilters(false)}>
						<LinkColor className="pl-5" onClick={() => clearFilters()}>
							Clear All Filters
						</LinkColor>
						<div className="flex flex-col gap-1">
							{categories.map((category) => (
								<div key={category} className="flex flex-row gap-1">
									<span>{!filter[category] ? "❌" : "✅"}</span>
									<LinkColor
										onClick={() => {
											if (filter[category]) {
												const newFilter = { ...filter };
												newFilter[category] = false;
												setFilter(newFilter);
											} else {
												const newFilter = { ...filter };
												newFilter[category] = true;
												setFilter(newFilter);
											}
										}}
									>
										{category}
									</LinkColor>
								</div>
							))}
						</div>
					</Dialog>
				)}
			</div>
			<div className="flex flex-col gap-2">
				{filteredWhitelistees.map((whitelistee) => (
					<div key={whitelistee.ckey} className="flex flex-col">
						<NameExpand name={whitelistee.ckey} />
						{whitelistee.whitelistStatus.split("|").join(" ")}
					</div>
				))}
			</div>
		</div>
	);
};
