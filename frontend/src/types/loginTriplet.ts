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

export type LoginHwid = {
	id: number;
	ckey: string;
	hwid: string;
	loginDate: string;
};

export type CkeyLink = {
	ckeyA: string;
	ckeyB: string;
	sharedIps: string[];
	sharedCids: string[];
	sharedHwids: string[];
};

export type MultiKeyTrace = {
	rootCkey: string;
	connectedCkeys: string[];
	links: CkeyLink[];
	depthReached: number;
	truncated: boolean;
};
