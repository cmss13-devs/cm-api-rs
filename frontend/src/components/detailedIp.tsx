import React, { useState } from "react";
import { Dialog } from "./dialog";
import { IpLookup } from "./ipLookup";
import { LinkColor } from "./link";

type DetailedIpProps = {
	ip: string;
};

export const DetailedIp: React.FC<DetailedIpProps> = (
	props: DetailedIpProps,
) => {
	const [open, setOpen] = useState(false);

	return (
		<>
			<LinkColor onClick={() => setOpen(true)} className="inline">
				{props.ip}
			</LinkColor>
			{open && (
				<Dialog open={open} toggle={() => setOpen(false)}>
					<IpLookup initialIp={props.ip} />
				</Dialog>
			)}
		</>
	);
};
