export type Stickyban = {
	id: number;
	identifier: string;
	reason: string;
	message: string;
	date: string;
	active: boolean;
	adminId?: number;
	adminCkey?: string;
};

export type StickybansMatchedCid = {
	id: number;
	cid: string;
	linkedStickyban: number;
};

export type StickybansMatchedCkey = {
	id: number;
	ckey: string;
	linkedStickyban: number;
	whitelisted: boolean;
};

export type StickybansMatchedIp = {
	id: number;
	ip: string;
	linkedStickyban: number;
};
