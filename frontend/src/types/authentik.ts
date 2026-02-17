export type GroupMember = {
	pk: number;
	username: string;
	ckey: string | null;
};

export type GroupMembersResponse = {
	groupName: string;
	members: GroupMember[];
};

export type UserGroupRequest = {
	ckey: string;
	group_name: string;
};

export type AuthentikSuccess = {
	message: string;
};

export type AuthentikError = {
	error: string;
	message: string;
};

export type GroupAdminRanksResponse = {
	groupName: string;
	adminRanks: string[];
	allowedRanks: string[];
};

export type UpdateAdminRanksRequest = {
	groupName: string;
	adminRanks: string[];
	instanceName: string;
};

export type GroupDisplayNameResponse = {
	groupName: string;
	displayName: string | null;
};

export type UpdateDisplayNameRequest = {
	groupName: string;
	displayName: string;
};

export type UserAdditionalTitlesResponse = {
	ckey: string;
	additionalTitles: string | null;
};

export type UpdateAdditionalTitlesRequest = {
	ckey: string;
	additionalTitles: string;
};

export type AuthentikUserFullResponse = {
	pk: number;
	uuid: string | null;
	uid: string;
	username: string;
	name: string;
	isActive: boolean;
	lastLogin: string | null;
	attributes: Record<string, unknown>;
	groups: string[];
};
