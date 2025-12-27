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
