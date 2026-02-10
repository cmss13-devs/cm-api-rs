import { createContext } from "react";

export type User = {
	username: string;
	ckey: string;
	email: string;
	groups: string[];
	isStaff: boolean;
	isManagement: boolean;
};

type GlobalType = {
	updateAndShowToast: (string: string) => void;
	user?: User;
};

export const GlobalContext = createContext<GlobalType | null>(null);
