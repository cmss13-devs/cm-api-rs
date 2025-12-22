export type LoginTriplet = {
	id: number;
	ckey: string;
	ip1: number;
	ip2: number;
	ip3: number;
	ip4: number;
	lastKnownCid: string;
	loginDate: string;
};

export type ConnectionHistory = {
	triplets?: LoginTriplet[];
	allCkeys?: string[];
	allCids?: string[];
	allIps?: string[];
};
