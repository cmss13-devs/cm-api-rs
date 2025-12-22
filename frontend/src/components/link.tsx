import React, { DetailedHTMLProps, HTMLAttributes } from "react";

interface LinkType
	extends DetailedHTMLProps<HTMLAttributes<HTMLDivElement>, HTMLDivElement> {
	to?: string;
}

export const LinkColor: React.FC<LinkType> = (props: LinkType) => {
	const { children, className, ...rest } = props;

	return (
		<div
			className={`cursor-pointer text-blue-600 inline hover:underline ${
				className ?? ""
			}`}
			{...rest}
		>
			{children}
		</div>
	);
};
