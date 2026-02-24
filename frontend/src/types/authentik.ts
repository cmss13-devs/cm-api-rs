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

export type AuthentikUserSearchResult = {
	pk: number;
	uuid: string | null;
	username: string;
	name: string;
	isActive: boolean;
};

export type LinkedOAuthSource = {
	connectionPk: number;
	name: string;
	slug: string;
	icon: string | null;
	identifier: string;
	parsedId: string | null;
};

export type AvailableOAuthSource = {
	slug: string;
	name: string;
	icon: string | null;
};

export type UserProfileResponse = {
	pk: number;
	uid: string;
	username: string;
	name: string;
	email: string | null;
	linkedSources: LinkedOAuthSource[];
	availableSources: AvailableOAuthSource[];
	authentikBaseUrl: string;
};

export type UpdateProfileRequest = {
	name?: string;
	email?: string;
};
