import { createContext } from "react";

export type User = {
	username: string;
	ckey: string;
	email: string;
	groups: string[];
	manageable: string[];
};

type GlobalType = {
	updateAndShowToast: (string: string) => void;
	user?: User;
};

export const GlobalContext = createContext<GlobalType | null>(null);
