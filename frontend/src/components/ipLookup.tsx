import React, {
	PropsWithChildren,
	useContext,
	useEffect,
	useState,
} from "react";
import { GlobalContext } from "../types/global";
import { TripletList } from "./tripletsList";
import { ConnectionHistory } from "../types/loginTriplet";
import { StickybanMatch } from "./stickybanMatch";
import { callApi } from "../helpers/api";

interface IpLookupProps extends PropsWithChildren {
	initialIp?: string;
	close?: () => void;
}

export const IpLookup: React.FC<IpLookupProps> = (props: IpLookupProps) => {
	const { initialIp } = props;

	const [ip, setIp] = useState<string>("");
	const [confirmedIp, setConfirmedIp] = useState("");

	const [ipData, setIpData] = useState<ConnectionHistory | null>(null);

	const [loading, setLoading] = useState(false);

	const global = useContext(GlobalContext);

	useEffect(() => {
		if (initialIp && !ipData) {
			updateIp(initialIp);
		}
	});

	const updateIp = (override?: string) => {
		setLoading(true);
		setConfirmedIp(override || ip);
		if (override) {
			setIp(override);
		}
		callApi(`/Connections/Ip?ip=${override ? override : ip}`).then((value) =>
			value.json().then((json) => {
				setLoading(false);
				if (json.status == 404) {
					global?.updateAndShowToast("No connections by IP.");
					if (props.close) props.close();
				} else {
					setIpData(json);
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
					updateIp();
				}}
			>
				<label htmlFor="ip">IP: </label>
				<input
					type="text"
					id="ip"
					name="ip"
					value={ip}
					onInput={(event) => {
						const target = event.target as HTMLInputElement;
						setIp(target.value);
					}}
				></input>
			</form>

			{ipData && <StickybanMatch ip={confirmedIp} />}
			{loading && <div className="text-2xl text-center">Loading...</div>}
			{ipData?.triplets && <TripletList triplets={ipData.triplets} />}
		</div>
	);
};
