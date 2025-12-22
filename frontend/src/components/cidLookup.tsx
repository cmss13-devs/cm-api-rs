import React, {
	PropsWithChildren,
	useContext,
	useEffect,
	useState,
} from "react";
import { GlobalContext } from "../types/global";
import { ConnectionHistory } from "../types/loginTriplet";
import { TripletList } from "./tripletsList";
import { StickybanMatch } from "./stickybanMatch";
import { callApi } from "../helpers/api";

interface CidLookupProps extends PropsWithChildren {
	initialCid?: string;
	close?: () => void;
}

export const CidLookup: React.FC<CidLookupProps> = (props: CidLookupProps) => {
	const { initialCid } = props;

	const [cid, setCid] = useState<string>("");
	const [cidData, setCidData] = useState<ConnectionHistory | null>(null);
	const [confirmedCid, setConfirmedCid] = useState("");

	const [loading, setLoading] = useState(false);

	const global = useContext(GlobalContext);

	useEffect(() => {
		if (initialCid && !cidData) {
			updateCid(initialCid);
		}
	});

	const updateCid = (override?: string) => {
		setLoading(true);
		setConfirmedCid(override || cid);
		if (override) {
			setCid(override);
		}
		callApi(`/Connections/Cid?cid=${override ? override : cid}`).then((value) =>
			value.json().then((json) => {
				setLoading(false);
				if (json.status == 404) {
					global?.updateAndShowToast("No connections by CID.");
					if (props.close) close;
				} else {
					setCidData(json);
				}
			}),
		);
	};

	return (
		<div className="flex flex-col gap-3">
			<form
				className="flex flex-row justify-center gap-3"
				onSubmit={(event) => {
					event.preventDefault();
					updateCid();
				}}
			>
				<label htmlFor="computer_id">CID: </label>
				<input
					type="text"
					id="computer_id"
					name="computer_id"
					value={cid}
					onInput={(event) => {
						const target = event.target as HTMLInputElement;
						setCid(target.value);
					}}
				></input>
			</form>

			{cidData && <StickybanMatch cid={confirmedCid} />}
			{loading && <div className="text-2xl text-center">Loading...</div>}
			{cidData?.triplets && <TripletList triplets={cidData.triplets} />}
		</div>
	);
};
