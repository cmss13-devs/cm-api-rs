import React from "react";
import { LoginTriplet } from "../types/loginTriplet";
import { NameExpand } from "./nameExpand";
import { DetailedIp } from "./detailedIp";
import { DetailedCid } from "./detailedCid";

type TripletListProps = {
	triplets: LoginTriplet[];
};

export const TripletList: React.FC<TripletListProps> = (
	props: TripletListProps,
) => {
	return (
		<div className="flex flex-col border-[#3f3f3f] border p-5 m-3 gap-1 max-h-[400px] md:max-h-[700px] overflow-auto">
			<table>
				{props.triplets.map((triplet) => (
					<tr key={triplet.id}>
						<td className="w-52">{triplet.loginDate}</td>
						<td>
							<NameExpand name={triplet.ckey} />
						</td>
						<td>
							<DetailedIp
								ip={`${triplet.ip1}.${triplet.ip2}.${triplet.ip3}.${triplet.ip4}`}
							/>
						</td>
						<td>
							<DetailedCid cid={triplet.lastKnownCid} />
						</td>
					</tr>
				))}
			</table>
		</div>
	);
};
