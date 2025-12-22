import { faXmark } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import React, { HTMLAttributes } from "react";

interface DialogPropsType extends HTMLAttributes<HTMLDialogElement> {
	open: boolean;
	toggle: () => void;
}

export const Dialog: React.FC<DialogPropsType> = (props: DialogPropsType) => {
	const { children, open, toggle, style, className, ...rest } = props;

	return (
		<>
			{open && (
				<div
					className="fixed w-full h-full left-0 top-0 opacity-50 foreground z-10"
					onClick={toggle}
				/>
			)}
			<dialog
				{...rest}
				open={open}
				className={`text-white w-full md:w-11/12 py-10 border border-[#3f3f3f] rounded shadow-xl foreground z-20 px-10 overflow-auto ${
					className ?? ""
				} md:min-w-[600px]`}
				style={{
					position: "fixed",
					top: "50%",
					left: "50%",
					transform: "translate(-50%, -50%)",
					...style,
				}}
			>
				<div
					className="absolute left-10 top-10 scale-150 cursor-pointer"
					onClick={toggle}
				>
					<FontAwesomeIcon icon={faXmark} />
				</div>
				{children}
			</dialog>
		</>
	);
};
