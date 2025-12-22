import React, { useEffect, useState } from "react";
import { Stickyban } from "../types/stickyban";
import { StickybanModal } from "./stickybanModal";
import { callApi } from "../helpers/api";

export const Stickybans: React.FC<Record<string, never>> = () => {
	const [stickybanData, setStickybanData] = useState<Stickyban[] | null>(null);

	useEffect(() => {
		if (!stickybanData) {
			callApi(`/Stickyban`).then((value) =>
				value.json().then((json) => setStickybanData(json)),
			);
		}
	});

	if (!stickybanData) {
		return <div className="flex flex-row justify-center">Loading...</div>;
	}

	return <StickybanModal stickybans={stickybanData} />;
};
