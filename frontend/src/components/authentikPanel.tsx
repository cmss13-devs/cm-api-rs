import type React from "react";
import { useCallback, useContext, useEffect, useId, useState } from "react";
import { callApi } from "../helpers/api";
import type {
  AuthentikError,
  GroupAdminRanksResponse,
  GroupMember,
  GroupMembersResponse,
} from "../types/authentik";
import { GlobalContext } from "../types/global";
import { Dialog } from "./dialog";
import { LinkColor } from "./link";
import { NameExpand } from "./nameExpand";

export const AuthentikPanel: React.FC = () => {
  const global = useContext(GlobalContext);

  const [availableGroups, setAvailableGroups] = useState<string[]>([]);
  const [groupsLoading, setGroupsLoading] = useState(true);
  const [selectedGroup, setSelectedGroup] = useState<string>("");
  const [members, setMembers] = useState<GroupMember[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [showAddDialog, setShowAddDialog] = useState(false);
  const [addCkey, setAddCkey] = useState("");
  const [addLoading, setAddLoading] = useState(false);

  const [showRemoveDialog, setShowRemoveDialog] = useState(false);
  const [memberToRemove, setMemberToRemove] = useState<GroupMember | null>(
    null
  );
  const [removeLoading, setRemoveLoading] = useState(false);

  const addCkeyInputId = useId();

  useEffect(() => {
    const fetchAllowedGroups = async () => {
      try {
        const response = await callApi("/Authentik/AllowedGroups");
        if (!response.ok) {
          throw new Error("Failed to fetch allowed groups");
        }
        const groups: string[] = await response.json();
        setAvailableGroups(groups);
        if (groups.length > 0) {
          setSelectedGroup(groups[0]);
        }
      } catch (err) {
        setError(
          err instanceof Error ? err.message : "Failed to load allowed groups"
        );
      } finally {
        setGroupsLoading(false);
      }
    };

    fetchAllowedGroups();
  }, []);

  const fetchGroupMembers = useCallback(async (groupName: string) => {
    setLoading(true);
    setError(null);
    try {
      const response = await callApi(
        `/Authentik/GroupMembers/${encodeURIComponent(groupName)}`
      );
      if (!response.ok) {
        const err: AuthentikError = await response.json();
        throw new Error(err.message || "Failed to fetch group members");
      }
      const data: GroupMembersResponse = await response.json();
      setMembers(data.members);
    } catch (err) {
      setError(err instanceof Error ? err.message : "An error occurred");
      setMembers([]);
    } finally {
      setLoading(false);
    }
  }, []);

  const handleAddUser = async () => {
    if (!addCkey.trim()) return;

    setAddLoading(true);
    try {
      const response = await callApi("/Authentik/AddUserToGroup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ckey: addCkey.trim(),
          group_name: selectedGroup,
        }),
      });

      if (!response.ok) {
        const err: AuthentikError = await response.json();
        throw new Error(err.message || "Failed to add user to group");
      }

      global?.updateAndShowToast(`Added ${addCkey} to ${selectedGroup}`);
      setShowAddDialog(false);
      setAddCkey("");
      fetchGroupMembers(selectedGroup);
    } catch (err) {
      global?.updateAndShowToast(
        err instanceof Error ? err.message : "Failed to add user"
      );
    } finally {
      setAddLoading(false);
    }
  };

  const handleRemoveUser = async () => {
    if (!memberToRemove) return;

    setRemoveLoading(true);
    try {
      const response = await callApi("/Authentik/RemoveUserFromGroup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ckey: memberToRemove.ckey,
          group_name: selectedGroup,
        }),
      });

      if (!response.ok) {
        const err: AuthentikError = await response.json();
        throw new Error(err.message || "Failed to remove user from group");
      }

      global?.updateAndShowToast(
        `Removed ${
          memberToRemove.ckey || memberToRemove.username
        } from ${selectedGroup}`
      );
      setShowRemoveDialog(false);
      setMemberToRemove(null);
      fetchGroupMembers(selectedGroup);
    } catch (err) {
      global?.updateAndShowToast(
        err instanceof Error ? err.message : "Failed to remove user"
      );
    } finally {
      setRemoveLoading(false);
    }
  };

  if (groupsLoading) {
    return <div>Loading...</div>;
  }

  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-xl font-bold">User Manager</h1>

      <div className="flex flex-row gap-2 items-center">
        <span>Group:</span>
        <select
          value={selectedGroup}
          onChange={(e) => setSelectedGroup(e.target.value)}
          className="bg-[#2a2a2a] border border-[#3f3f3f] rounded px-2 py-1 text-white"
          disabled={availableGroups.length === 0}
        >
          {availableGroups.map((group) => (
            <option key={group} value={group}>
              {group}
            </option>
          ))}
        </select>
        <LinkColor onClick={() => setShowAddDialog(true)}>
          Add User to Group
        </LinkColor>
      </div>

      {error && <div className="text-red-400">Error: {error}</div>}

      {loading && <div>Loading members...</div>}

      {!loading && !error && (
        <div className="flex flex-col gap-2">
          <h2 className="text-lg font-semibold">
            Members of {selectedGroup} ({members.length})
          </h2>
          {members.length === 0 ? (
            <div className="text-gray-400">No members in this group</div>
          ) : (
            <div className="flex flex-col gap-1">
              {members.map((member) => (
                <div
                  key={member.pk}
                  className="flex flex-row gap-2 items-center border-b border-[#3f3f3f] py-1"
                >
                  <span className="min-w-[150px]">{member.username}</span>
                  {member.ckey && (
                    <span className="text-gray-400">
                      (<NameExpand name={member.ckey} />)
                    </span>
                  )}
                  <LinkColor
                    className="ml-auto text-red-400"
                    onClick={() => {
                      setMemberToRemove(member);
                      setShowRemoveDialog(true);
                    }}
                  >
                    Remove
                  </LinkColor>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <RanksPanel selectedGroup={selectedGroup} />

      {showAddDialog && (
        <Dialog open={showAddDialog} toggle={() => setShowAddDialog(false)}>
          <div className="flex flex-col gap-4 pt-6">
            <h2 className="text-lg font-semibold">
              Add User to {selectedGroup}
            </h2>
            <div className="flex flex-col gap-2">
              <label htmlFor={addCkeyInputId}>Ckey:</label>
              <input
                id={addCkeyInputId}
                type="text"
                value={addCkey}
                onChange={(e) => setAddCkey(e.target.value)}
                placeholder="Enter ckey"
                className="bg-[#2a2a2a] border border-[#3f3f3f] rounded px-2 py-1 text-white"
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleAddUser();
                }}
              />
            </div>
            <div className="flex flex-row gap-2">
              <button
                type="button"
                onClick={handleAddUser}
                disabled={addLoading || !addCkey.trim()}
                className="bg-green-600 hover:bg-green-700 disabled:bg-gray-600 px-4 py-2 rounded"
              >
                {addLoading ? "Adding..." : "Add User"}
              </button>
              <button
                type="button"
                onClick={() => setShowAddDialog(false)}
                className="bg-gray-600 hover:bg-gray-700 px-4 py-2 rounded"
              >
                Cancel
              </button>
            </div>
          </div>
        </Dialog>
      )}

      {showRemoveDialog && memberToRemove && (
        <Dialog
          open={showRemoveDialog}
          toggle={() => setShowRemoveDialog(false)}
        >
          <div className="flex flex-col gap-4 pt-6">
            <h2 className="text-lg font-semibold">Confirm Removal</h2>
            <p>
              Are you sure you want to remove{" "}
              <strong>{memberToRemove.ckey || memberToRemove.username}</strong>{" "}
              from the <strong>{selectedGroup}</strong> group?
            </p>
            <div className="flex flex-row gap-2">
              <button
                type="button"
                onClick={handleRemoveUser}
                disabled={removeLoading}
                className="bg-red-600 hover:bg-red-700 disabled:bg-gray-600 px-4 py-2 rounded"
              >
                {removeLoading ? "Removing..." : "Remove"}
              </button>
              <button
                type="button"
                onClick={() => setShowRemoveDialog(false)}
                className="bg-gray-600 hover:bg-gray-700 px-4 py-2 rounded"
              >
                Cancel
              </button>
            </div>
          </div>
        </Dialog>
      )}
    </div>
  );
};

const RanksPanel = (props: { selectedGroup: string }) => {
  const global = useContext(GlobalContext);

  const [adminRanks, setAdminRanks] = useState<string[]>([]);
  const [pendingRanks, setPendingRanks] = useState<string[]>([]);
  const [allowedRanks, setAllowedRanks] = useState<string[]>([]);
  const [ranksLoading, setRanksLoading] = useState(false);
  const [ranksError, setRanksError] = useState<string | null>(null);
  const [ranksSaving, setRanksSaving] = useState(false);

  const { selectedGroup } = props;

  const fetchAdminRanks = useCallback(async (groupName: string) => {
    setRanksLoading(true);
    setRanksError(null);
    try {
      const response = await callApi(
        `/Authentik/GroupAdminRanks/${encodeURIComponent(groupName)}`
      );
      if (!response.ok) {
        if (response.status === 403) {
          // User doesn't have management permissions - just clear ranks
          setAdminRanks([]);
          setPendingRanks([]);
          setAllowedRanks([]);
          return;
        }
        const err: AuthentikError = await response.json();
        throw new Error(err.message || "Failed to fetch admin ranks");
      }
      const data: GroupAdminRanksResponse = await response.json();
      setAdminRanks(data.adminRanks);
      setPendingRanks(data.adminRanks);
      setAllowedRanks(data.allowedRanks);
    } catch (err) {
      setRanksError(err instanceof Error ? err.message : "An error occurred");
      setAdminRanks([]);
      setPendingRanks([]);
      setAllowedRanks([]);
    } finally {
      setRanksLoading(false);
    }
  }, []);

  useEffect(() => {
    if (selectedGroup) {
      fetchAdminRanks(selectedGroup);
    }
  }, [selectedGroup, fetchAdminRanks]);

  const handleToggleRank = (rank: string) => {
    setPendingRanks((prev) =>
      prev.includes(rank) ? prev.filter((r) => r !== rank) : [...prev, rank]
    );
  };

  const handleSaveRanks = async () => {
    setRanksSaving(true);
    try {
      const response = await callApi("/Authentik/GroupAdminRanks", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          groupName: selectedGroup,
          adminRanks: pendingRanks,
        }),
      });

      if (!response.ok) {
        const err: AuthentikError = await response.json();
        throw new Error(err.message || "Failed to update admin ranks");
      }

      setAdminRanks(pendingRanks);
      global?.updateAndShowToast(`Updated admin ranks for ${selectedGroup}`);
    } catch (err) {
      global?.updateAndShowToast(
        err instanceof Error ? err.message : "Failed to update admin ranks"
      );
    } finally {
      setRanksSaving(false);
    }
  };

  const handleResetRanks = () => {
    setPendingRanks(adminRanks);
  };

  const ranksChanged =
    JSON.stringify([...adminRanks].sort()) !==
    JSON.stringify([...pendingRanks].sort());

  return (
    <>
      {allowedRanks.length > 0 && (
        <div className="flex flex-col gap-2">
          <h2 className="text-lg font-semibold">Admin Ranks</h2>
          {ranksLoading ? (
            <div>Loading admin ranks...</div>
          ) : ranksError ? (
            <div className="text-red-400">Error: {ranksError}</div>
          ) : (
            <>
              <div className="flex flex-col gap-2">
                {allowedRanks.map((rank) => (
                  <label
                    key={rank}
                    className="flex flex-row gap-2 items-center cursor-pointer"
                  >
                    <input
                      type="checkbox"
                      checked={pendingRanks.includes(rank)}
                      onChange={() => handleToggleRank(rank)}
                      disabled={ranksSaving}
                      className="w-4 h-4 accent-blue-500"
                    />
                    <span className={ranksSaving ? "text-gray-500" : ""}>
                      {rank}
                    </span>
                  </label>
                ))}
              </div>
              {ranksChanged && (
                <div className="flex flex-row gap-2 mt-2">
                  <button
                    type="button"
                    onClick={handleSaveRanks}
                    disabled={ranksSaving}
                    className="bg-green-600 hover:bg-green-700 disabled:bg-gray-600 px-4 py-2 rounded"
                  >
                    {ranksSaving ? "Saving..." : "Save"}
                  </button>
                  <button
                    type="button"
                    onClick={handleResetRanks}
                    disabled={ranksSaving}
                    className="bg-gray-600 hover:bg-gray-700 disabled:bg-gray-600 px-4 py-2 rounded"
                  >
                    Reset
                  </button>
                </div>
              )}
            </>
          )}
        </div>
      )}
    </>
  );
};
