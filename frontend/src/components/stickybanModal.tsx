import React, { useState } from "react";
import {
	Stickyban,
	StickybansMatchedCid,
	StickybansMatchedCkey,
	StickybansMatchedIp,
} from "../types/stickyban";
import { LinkColor } from "./link";
import { Dialog } from "./dialog";
import { callApi } from "../helpers/api";
import { Expand } from "./expand";

type StickybanModalProps = {
	stickybans: Stickyban[];
};

export const StickybanModal: React.FC<StickybanModalProps> = (
	props: StickybanModalProps,
) => {
	const { stickybans } = props;

	return (
		<div className="pt-10">
			<div className="flex flex-row justify-center text-xl">Stickyban Menu</div>
			<div className="overflow-auto max-h-[800px] border-[#3f3f3f] border p-3">
				<table className="w-full">
					<tbody className="">
						<tr>
							<th>Identifier</th>
							<th>Message</th>
							<th>Reason</th>
							<th>Admin</th>
							<th>Actions</th>
						</tr>
						{stickybans.map((stickyban) => (
							<StickybanEntry stickyban={stickyban} key={stickyban.id} />
						))}
					</tbody>
				</table>
			</div>
		</div>
	);
};

const StickybanEntry = (props: { stickyban: Stickyban }) => {
	const { stickyban } = props;

	return (
		<tr className={`${stickyban.active ? "" : "text-gray-500"}`}>
			<td className="border-r border-b p-2 border-[#3f3f3f]">
				{stickyban.identifier}
			</td>
			<td className="border-r border-b p-2 border-[#3f3f3f]">
				{stickyban.message}
			</td>
			<td className="border-r border-b p-2 border-[#3f3f3f]">
				{stickyban.reason.trim().length > 30 ? (
					<span>
						<span>{stickyban.reason.trim().substring(0, 27)}</span>
						<Expand label={"..."} value={stickyban.reason.trim()} />
					</span>
				) : (
					stickyban.reason.trim()
				)}
			</td>
			<td className="border-r border-b p-2 border-[#3f3f3f]">
				{stickyban.adminCkey ?? "AdminBot"}
			</td>
			<td className="p-2 border-b border-[#3f3f3f]">
				<ExpandDetails stickyban={stickyban} />
			</td>
		</tr>
	);
};

const ExpandDetails = (props: { stickyban: Stickyban }) => {
	const { stickyban } = props;

	const [cids, setCids] = useState<StickybansMatchedCid[] | null>(null);
	const [ckeys, setCkeys] = useState<StickybansMatchedCkey[] | null>(null);
	const [ips, setIps] = useState<StickybansMatchedIp[] | null>(null);

	const [open, setOpen] = useState(false);

	const check = () => {
		setOpen(true);

		callApi(`/Stickyban/${stickyban.id}/Match/Cid`).then((value) =>
			value.json().then((json) => {
				setCids(json);
			}),
		);

		callApi(`/Stickyban/${stickyban.id}/Match/Ckey`).then((value) =>
			value.json().then((json) => {
				setCkeys(json);
			}),
		);

		callApi(`/Stickyban/${stickyban.id}/Match/Ip`).then((value) =>
			value.json().then((json) => {
				setIps(json);
			}),
		);
	};

	return (
		<>
			<LinkColor onClick={() => check()}>Details</LinkColor>
			{open && (
				<Dialog open={!!cids} toggle={() => setOpen(false)} className="expand">
					<div className="flex flex-col gap-2 pt-10">
						<div>CIDs: {cids && cids.map((cid) => cid.cid).join(", ")}</div>
						<div>
							CKEYs:{" "}
							{ckeys &&
								ckeys
									.filter((ckey) => ckey.ckey)
									.map((ckey) => ckey.ckey)
									.join(", ")}
						</div>
						<div>IPs: {ips && ips.map((ip) => ip.ip).join(", ")}</div>
					</div>
				</Dialog>
			)}
		</>
	);
};
