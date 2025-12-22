import React, { useState } from "react";
import { LinkColor } from "./link";
import { Dialog } from "./dialog";

type ExpandProps = {
	label: string;
	value: string;
};

export const Expand: React.FC<ExpandProps> = (props: ExpandProps) => {
	const [open, setOpen] = useState(false);

	return (
		<>
			<LinkColor onClick={() => setOpen(true)}>{props.label}</LinkColor>
			{open && (
				<Dialog open={open} toggle={() => setOpen(false)} className="expand">
					<div className="pt-10">{props.value}</div>
				</Dialog>
			)}
		</>
	);
};
