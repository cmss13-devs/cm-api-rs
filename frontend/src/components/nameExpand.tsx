import React from "react";
import { LinkColor } from "./link";
import { Link } from "react-router-dom";

interface NameExpandProps {
	name?: string;
}

export const NameExpand: React.FC<NameExpandProps> = (
	props: NameExpandProps,
) => {
	return (
		<>
			<LinkColor className="inline">
				<Link to={`/user/${props.name}`}>{props.name}</Link>
			</LinkColor>
		</>
	);
};
