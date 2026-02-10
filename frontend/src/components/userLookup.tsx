import React, {
  createContext,
  type PropsWithChildren,
  useCallback,
  useContext,
  useEffect,
  useState,
} from "react";
import { useLoaderData, useNavigate, useSearchParams } from "react-router-dom";
import { useDebounce } from "use-debounce";
import { callApi } from "../helpers/api";
import { GlobalContext } from "../types/global";
import type { ConnectionHistory } from "../types/loginTriplet";
import type { Ticket } from "../types/ticket";
import { DetailedCid } from "./detailedCid";
import { DetailedIp } from "./detailedIp";
import { Dialog } from "./dialog";
import { Expand } from "./expand";
import { LinkColor } from "./link";
import { NameExpand } from "./nameExpand";
import { StickybanMatch } from "./stickybanMatch";
import { TicketModal } from "./ticketmodal";
import { TripletList } from "./tripletsList";

type ActiveLookupType = {
  updateUser: (_args: UpdateUserArguments) => void;
};

const ActiveLookupContext = createContext<ActiveLookupType | null>(null);

interface LookupMenuProps extends PropsWithChildren {
  value?: string;
  discordId?: string;
  close?: () => void;
}

type UpdateUserArguments = {
  userCkey?: string;
  userDiscordId?: string;
};

export const LookupMenu: React.FC<LookupMenuProps> = (
  props: LookupMenuProps
) => {
  const [user, setUser] = useState<string>("");
  const [userData, setUserData] = useState<Player | null>(null);
  const [loading, setLoading] = useState(false);
  const global = useContext(GlobalContext);

  const { value, discordId, close } = props;

  const updateUser = useCallback(
    (args: UpdateUserArguments) => {
      const { userCkey, userDiscordId } = args;
      setLoading(true);
      const re = /[\\^]|[^a-z0-9@]/g;
      const userCkeyChecked = userCkey?.toLowerCase().replace(re, "");
      callApi(
        userCkeyChecked
          ? `/User?ckey=${userCkeyChecked}`
          : `/User?discord_id=${userDiscordId}`
      ).then((value) => {
        if (value.status === 404) {
          global?.updateAndShowToast("Failed to find user.");
          if (close) {
            close();
          }
        } else {
          value.json().then((json) => {
            setLoading(false);
            setUserData(json);
          });
        }
      });
    },
    [setLoading, setUserData, close, global]
  );

  const potentialUser = useLoaderData() as string;

  useEffect(() => {
    if (loading) return;

    if (discordId && !userData) {
      updateUser({ userDiscordId: discordId });
      return;
    }
    if (value && !userData) {
      updateUser({ userCkey: value });
      return;
    }

    if (!potentialUser) return;

    const re = /[\\^]|[^a-z0-9@]/g;
    const checked = potentialUser.toLowerCase().replace(re, "");

    if (potentialUser && (!userData || userData.ckey !== checked)) {
      updateUser({ userCkey: potentialUser as string });
    }
  }, [value, userData, discordId, updateUser, potentialUser, user, loading]);

  const nav = useNavigate();

  return (
    <ActiveLookupContext.Provider value={{ updateUser: updateUser }}>
      {!value && !discordId && (
        <form
          className="flex flex-row justify-center gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            nav(`/user/${user}`);
          }}
        >
          <label htmlFor="ckey">User: </label>
          <input
            type="text"
            id="ckey"
            name="ckey"
            value={user}
            onInput={(event) => {
              const target = event.target as HTMLInputElement;
              setUser(target.value);
            }}
          ></input>
        </form>
      )}

      {loading && <div className="text-xl text-center">Loading...</div>}

      {userData && <UserModal player={userData} />}
    </ActiveLookupContext.Provider>
  );
};

export interface Player {
  id: number;
  ckey: string;
  lastLogin: string;
  isPermabanned: boolean;
  permabanReason?: string;
  permabanDate?: string;
  isTimeBanned: boolean;
  timeBanReason?: string;
  timeBanAdminId?: number;
  timeBanDate?: string;
  lastKnownIp: string;
  lastKnownCid: string;
  timeBanExpiration?: number;
  migratedNotes: boolean;
  migratedBans: boolean;
  permabanAdminId?: number;
  stickybanWhitelisted?: boolean;
  discordLinkId?: number;
  whitelistStatus?: string;
  byondAccountAge?: string;
  firstJoinDate?: string;
  notes?: PlayerNote[];
  jobBans?: PlayerJobBan[];
  permabanAdminCkey?: string;
  timeBanAdminCkey?: string;
  discordId?: number;
}

const UserModal = (props: { player: Player }) => {
  const { player } = props;

  const { ckey } = player;

  return (
    <div className="flex flex-col gap-3">
      <div className="text-center text-2xl underline">{ckey}</div>

      <div className="flex flex-col md:flex-row justify-center gap-2">
        <IsBannedModal player={player} />
        <div>
          <StickybanMatch ckey={player.ckey} />
        </div>
      </div>

      {import.meta.env.VITE_USE_ACTIONS && (
        <PlayerActionsModal player={player} />
      )}

      <UserDetailsModal player={player} />

      <div className="flex flex-row">
        <div className="flex flex-col gap-3 grow">
          <UserNotesModal player={player} />
          <UserJobBansModal player={player} />
          <KnownAltsModal player={player} />
        </div>
      </div>
    </div>
  );
};

const IsBannedModal = (props: { player: Player }) => {
  const { player } = props;
  const {
    isPermabanned,
    permabanDate,
    permabanReason,
    permabanAdminCkey,
    isTimeBanned,
    timeBanDate,
    timeBanReason,
    timeBanAdminCkey,
    timeBanExpiration,
  } = player;

  if (isPermabanned) {
    return (
      <div className="red-alert-bg p-3">
        <div className="foreground p-2">
          <div className="text-2xl">PERMABANNED</div>
          <div>Placed: {permabanDate}</div>
          <div>Reason: {permabanReason}</div>
          <div>By: {permabanAdminCkey}</div>
        </div>
      </div>
    );
  }

  if (isTimeBanned && timeBanExpiration) {
    const byondEpoch = Date.parse("01 Jan 2000 00:00:00 GMT");
    const approxUnban = byondEpoch + timeBanExpiration * 60000;

    if (Date.now() > approxUnban) {
      return;
    }

    const unbanDate = new Date(approxUnban).toString();

    return (
      <div className="purple-alert-bg p-3">
        <div className="foreground p-2">
          <div className="text-2xl">TEMPBANNED</div>
          <div>
            Placed: {timeBanDate} Expires: {unbanDate}
          </div>
          <div>Reason: {timeBanReason}</div>
          <div>By: {timeBanAdminCkey}</div>
        </div>
      </div>
    );
  }
};

const PlayerActionsModal = (props: { player: Player }) => {
  const { player } = props;

  return (
    <div className="flex flex-row gap-3 justify-center">
      <PermaBanButton player={player} />
      <TimeBanButton player={player} />
    </div>
  );
};

const PermaBanButton = (props: { player: Player }) => {
  const { isPermabanned } = props.player;

  if (isPermabanned) {
    return (
      <div className="cursor-pointer red-alert-bg p-3">
        <div className="foreground p-3">Remove Permaban</div>
      </div>
    );
  }

  return (
    <div className="cursor-pointer red-alert-bg p-3">
      <div className="foreground p-3">Permaban User</div>
    </div>
  );
};

const TimeBanButton = (props: { player: Player }) => {
  const { isTimeBanned } = props.player;

  if (isTimeBanned) {
    return (
      <div className="cursor-pointer purple-alert-bg p-3">
        <div className="foreground p-3">Remove Timeban</div>
      </div>
    );
  }

  return (
    <div className="cursor-pointer purple-alert-bg p-3">
      <div className="foreground p-3">Time Ban User</div>
    </div>
  );
};

type VpnWhitelist = {
  ckey: string;
  adminCkey: string;
};

type DiscourseUser = {
  ckey: string;
  discourseUserId: number;
  discourseUsername: string;
};

const UserDetailsModal = (props: { player: Player }) => {
  const { player } = props;

  const {
    lastLogin,
    lastKnownCid,
    lastKnownIp,
    byondAccountAge,
    firstJoinDate,
    discordId,
    ckey,
  } = player;

  const global = useContext(GlobalContext);

  const [tickets, setViewTickets] = useState(false);
  const [playtime, setViewPlaytime] = useState(false);
  const [vpnWhitelist, setVpnWhitelist] = useState<
    VpnWhitelist | null | undefined
  >(undefined);
  const [discourseUser, setDiscourseUser] = useState<
    DiscourseUser | null | undefined
  >(undefined);

  useEffect(() => {
    setViewTickets(false);
    setVpnWhitelist(undefined);
    setDiscourseUser(undefined);
  }, [player, setViewTickets]);

  useEffect(() => {
    if (vpnWhitelist === undefined) {
      callApi(`/User/VpnWhitelist?ckey=${ckey}`).then((response) => {
        if (response.status === 200) {
          response.json().then((json) => setVpnWhitelist(json));
        } else {
          setVpnWhitelist(null);
        }
      });
    }
  }, [ckey, vpnWhitelist]);

  useEffect(() => {
    if (discourseUser === undefined) {
      callApi(`/Authentik/DiscourseUser/${ckey}`).then((response) => {
        if (response.status === 200) {
          response.json().then((json) => setDiscourseUser(json));
        } else {
          setDiscourseUser(null);
        }
      });
    }
  }, [ckey, discourseUser]);

  const potentialUser = useLoaderData() as string;
  const nav = useNavigate();

  const [searchParams] = useSearchParams();

  useEffect(() => {
    if (searchParams.get("viewTickets")) {
      setViewTickets(true);
    }
  }, [searchParams]);

  return (
    <>
      <div className="flex flex-col items-center md:items-start md:flex-row gap-3 justify-center">
        <div className="flex flex-row gap-3">
          <div className="underline">
            <div>Last Seen:</div>
            <div>Last Known CID:</div>
            <div>Last Known IP:</div>
          </div>

          <div>
            <div>{lastLogin}</div>
            <div>
              <DetailedCid cid={lastKnownCid} />
            </div>
            <div>
              <DetailedIp ip={lastKnownIp} />
            </div>
          </div>
        </div>

        <div className="flex flex-row gap-3">
          <div className="underline">
            <div>BYOND Account Age:</div>
            <div>First Join Date:</div>
            <div>Discord ID:</div>
          </div>

          <div>
            <div>{byondAccountAge ?? "Unknown"}</div>
            <div>{firstJoinDate ?? "Unknown"}</div>
            {discordId ? (
              <LinkColor
                onClick={() => {
                  global?.updateAndShowToast("Copied to clipboard.");
                  navigator.clipboard.writeText(`${discordId}`);
                }}
              >
                {discordId}
              </LinkColor>
            ) : (
              <div>Not Linked</div>
            )}
          </div>
        </div>
        <div className="flex flex-col">
          <ConnectionType
            label={"View Full Connection History"}
            path={"/Connections/Ckey?ckey="}
            value={ckey}
          />
          <ConnectionType
            label={"View Full Connections By All CIDs"}
            path={"/Connections/FullByAllCid?ckey="}
            value={ckey}
          />
          <ConnectionType
            label={"View Full Connections By All IPs"}
            path={"/Connections/FullByAllIps?ckey="}
            value={ckey}
          />
        </div>
      </div>
      <div className="flex flex-col">
        <div className="flex flex-row justify-center gap-2">
          {player.whitelistStatus && (
            <>
              <Expand
                value={player.whitelistStatus.split("|").join("\n")}
                label="View Role Whitelists"
              />
              {"|"}
            </>
          )}
          <LinkColor
            onClick={() => {
              if (!potentialUser) {
                nav(`/user/${ckey}/?viewTickets=1`);
              } else {
                setViewTickets(true);
              }
            }}
          >
            View Tickets
          </LinkColor>
          {tickets && (
            <Dialog open={tickets} toggle={() => setViewTickets(false)}>
              <div className="pt-5">
                <UserTickets ckey={player.ckey} />
              </div>
            </Dialog>
          )}
          {"|"}
          <LinkColor onClick={() => setViewPlaytime(true)}>
            View Playtime
          </LinkColor>
          {discourseUser && (
            <>
              {"|"}
              <LinkColor
                onClick={() =>
                  window.open(
                    `https://forum.cm-ss13.com/admin/users/${discourseUser.discourseUserId}/${discourseUser.discourseUsername}`,
                    "_blank"
                  )
                }
              >
                View Forum Account
              </LinkColor>
            </>
          )}
          {playtime && (
            <Dialog
              open={playtime}
              toggle={() => setViewPlaytime(false)}
              className="h-[80%]"
            >
              <div className="pt-5">
                <UserPlaytime id={player.id} />
              </div>
            </Dialog>
          )}
          {"|"}
          <VpnWhitelistToggle
            ckey={ckey}
            vpnWhitelist={vpnWhitelist}
            setVpnWhitelist={setVpnWhitelist}
          />
        </div>
      </div>
    </>
  );
};

const UserTickets = (props: { ckey: string }) => {
  const [tickets, setTicketData] = useState<Ticket[] | undefined>();
  const [page, setPage] = useState(1);
  const [activePage, setActivePage] = useState(1);
  const [errored, setErrored] = useState(false);

  const [fromDate, setFromDate] = useState<Date>();
  const [toDate, setToDate] = useState<Date>();

  const [debouncedFrom] = useDebounce(fromDate, 500);
  const [debouncedTo] = useDebounce(toDate, 500);

  // biome-ignore lint/style/noNonNullAssertion: this has to exist
  const glob = useContext(GlobalContext)!;

  const { updateAndShowToast } = glob;

  const { ckey } = props;

  const encodeDate = (date: Date) => {
    return date.toISOString().slice(0, 19).replace("T", " ");
  };

  useEffect(() => {
    if (page !== activePage) {
      setTicketData(undefined);
    }

    if ((debouncedFrom && !debouncedTo) || (!debouncedFrom && debouncedTo))
      return;

    if (!errored) {
      let dateString = "";
      if (debouncedFrom && debouncedTo) {
        const to = new Date(debouncedTo);
        to.setUTCHours(23, 59, 59);
        dateString = `&from=${encodeDate(debouncedFrom)}&to=${encodeDate(to)}`;
      }
      callApi(`/Ticket/User/${ckey}/?page=${page}${dateString}`).then(
        (value) => {
          if (value.status !== 200) {
            updateAndShowToast("No more tickets.");
            if (page === 1) {
              setErrored(true);
            } else {
              setPage(page - 1);
            }
            return;
          }

          value.json().then((json) => {
            setTicketData(json);
            setActivePage(page);
          });
        }
      );
    }
  }, [
    setTicketData,
    page,
    setPage,
    ckey,
    activePage,
    setActivePage,
    updateAndShowToast,
    errored,

    debouncedFrom,
    debouncedTo,
  ]);

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-row justify-center gap-3">
        <div className="flex flex-row gap-1">
          From:
          <input
            type="date"
            onChange={(val) => {
              const date = val.target.valueAsDate;
              if (date) setFromDate(date);
            }}
          />
        </div>
        <div className="flex flex-row gap-1">
          To:
          <input
            type="date"
            onChange={(val) => {
              const date = val.target.valueAsDate;
              if (date) setToDate(date);
            }}
          />
        </div>
      </div>
      <div className="flex flex-row justify-center gap-3">
        {page > 1 && (
          <LinkColor
            className="text-xl"
            onClick={() => setPage((x) => Math.max(x - 1, 1))}
          >
            {"<-"}
          </LinkColor>
        )}
        <div>Page {page}</div>
        <LinkColor className="text-xl" onClick={() => setPage((x) => x + 1)}>
          {"->"}
        </LinkColor>
      </div>
      {tickets && <TicketModal tickets={tickets} />}
      {!tickets && !errored && (
        <div className="flex flex-row justify-center">Waiting...</div>
      )}
      {errored && (
        <div className="flex flex-row justify-center">No tickets for user.</div>
      )}
    </div>
  );
};

type Playtime = {
  id: number;
  playerId: number;
  roleId: string;
  totalMinutes: number;
};

const UserPlaytime = (props: { id: number }) => {
  const [playtimeData, setPlaytimeData] = useState<Playtime[] | undefined>();

  useEffect(() => {
    callApi(`/User/${props.id}/Playtime`).then((value) =>
      value.json().then((json) => setPlaytimeData(json))
    );
  }, [props.id]);

  const getRecentPlaytime = (when: number) => {
    setPlaytimeData(undefined);
    callApi(`/User/${props.id}/Playtime/${when}`).then((value) =>
      value.json().then((json) => setPlaytimeData(json))
    );
  };

  if (!playtimeData) return "Loading...";

  const totalMinutes: number = playtimeData.reduce(
    (currentValue, playtime) => playtime.totalMinutes + currentValue,
    0
  );

  return (
    <div className="flex flex-col">
      <div className="flex flex-row gap-2">
        <LinkColor onClick={() => getRecentPlaytime(30)}>
          Last 30 days
        </LinkColor>{" "}
        |{" "}
        <LinkColor onClick={() => getRecentPlaytime(60)}>
          Last 60 Days
        </LinkColor>{" "}
        |{" "}
        <LinkColor onClick={() => getRecentPlaytime(90)}>
          Last 90 Days
        </LinkColor>
        |{" "}
        <LinkColor onClick={() => getRecentPlaytime(180)}>
          Last 6 Months
        </LinkColor>
      </div>
      <div className="flex flex-col gap-2 mt-2">
        <div className="underline">
          Total: {Math.round((totalMinutes / 60) * 100) / 100} hours
        </div>
        {playtimeData
          .sort((a, b) => b.totalMinutes - a.totalMinutes)
          .map((playtime) => (
            <div key={playtime.id}>
              {playtime.roleId}:{" "}
              {Math.round((playtime.totalMinutes / 60) * 100) / 100} hours
            </div>
          ))}
      </div>
    </div>
  );
};

const VpnWhitelistToggle = (props: {
  ckey: string;
  vpnWhitelist: VpnWhitelist | null | undefined;
  setVpnWhitelist: (value: VpnWhitelist | null | undefined) => void;
}) => {
  const { ckey, vpnWhitelist, setVpnWhitelist } = props;
  const [loading, setLoading] = useState(false);
  const [confirmAdd, setConfirmAdd] = useState(false);
  const [confirmRemove, setConfirmRemove] = useState(false);
  const global = useContext(GlobalContext);

  const addVpnWhitelist = () => {
    setLoading(true);
    callApi(`/User/VpnWhitelist?ckey=${ckey}`, { method: "POST" }).then(
      (response) => {
        setLoading(false);
        setConfirmAdd(false);
        if (response.status === 201) {
          global?.updateAndShowToast(`Added VPN whitelist for ${ckey}.`);
          setVpnWhitelist(undefined); // Trigger refetch
        } else {
          global?.updateAndShowToast("Failed to add VPN whitelist.");
        }
      }
    );
  };

  const removeVpnWhitelist = () => {
    setLoading(true);
    callApi(`/User/VpnWhitelist?ckey=${ckey}`, { method: "DELETE" }).then(
      (response) => {
        setLoading(false);
        setConfirmRemove(false);
        if (response.status === 200) {
          global?.updateAndShowToast(`Removed VPN whitelist for ${ckey}.`);
          setVpnWhitelist(null);
        } else {
          global?.updateAndShowToast("Failed to remove VPN whitelist.");
        }
      }
    );
  };

  if (vpnWhitelist === undefined) {
    return <span>Loading...</span>;
  }

  if (loading) {
    return <span>Processing...</span>;
  }

  if (vpnWhitelist) {
    return (
      <span className="flex flex-row gap-1">
        <span className="text-green-500">VPN Whitelisted</span>
        <span>(by {vpnWhitelist.adminCkey})</span>
        {"|"}
        {!confirmRemove ? (
          <LinkColor onClick={() => setConfirmRemove(true)}>
            Remove VPN Whitelist
          </LinkColor>
        ) : (
          <LinkColor
            onClick={() => removeVpnWhitelist()}
            className="text-red-500"
          >
            Confirm Remove
          </LinkColor>
        )}
      </span>
    );
  }

  return (
    <>
      {!confirmAdd ? (
        <LinkColor onClick={() => setConfirmAdd(true)}>
          Add VPN Whitelist
        </LinkColor>
      ) : (
        <LinkColor onClick={() => addVpnWhitelist()} className="text-red-500">
          Confirm Add
        </LinkColor>
      )}
    </>
  );
};

const ConnectionType = (props: {
  label: string;
  path: string;
  value: string;
}) => {
  const [open, setOpen] = useState(false);

  const { path, value, label } = props;

  return (
    <>
      <LinkColor onClick={() => setOpen(true)}>{label}</LinkColor>
      {open && (
        <Dialog
          open={open}
          toggle={() => setOpen(false)}
          className="min-h-11/12"
        >
          <ConnectionTypeDetails path={path} value={value} />
        </Dialog>
      )}
    </>
  );
};

const ConnectionTypeDetails = (props: {
  path: string;
  value: string;
  viewCkeys?: boolean;
  viewCids?: boolean;
  viewIps?: boolean;
}) => {
  const [connectionData, setConnectionData] =
    useState<ConnectionHistory | null>(null);

  const { path, value } = props;

  useEffect(() => {
    if (!connectionData) {
      callApi(`${path}${value}`).then((value) =>
        value.json().then((json) => setConnectionData(json))
      );
    }
  }, [connectionData, path, value]);

  if (!connectionData) {
    return <div className="text-center">Loading...</div>;
  }

  return (
    <div className="flex flex-col">
      <div className="flex flex-row justify-center gap-1">
        {!!connectionData.allCkeys && (
          <Expand
            label={"View All CKEYs"}
            value={connectionData.allCkeys.join(", ")}
          />
        )}
        {!!connectionData.allCkeys && !!connectionData.allCids && <div>-</div>}
        {!!connectionData.allCids && (
          <Expand
            label={"View All CIDs"}
            value={connectionData.allCids.join(", ")}
          />
        )}
        {!!connectionData.allCids && !!connectionData.allIps && <div>-</div>}
        {!!connectionData.allIps && (
          <Expand
            label={"View All IPs"}
            value={connectionData.allIps.join(", ")}
          />
        )}
      </div>
      {connectionData.triplets && (
        <TripletList triplets={connectionData.triplets} />
      )}
    </div>
  );
};

interface PlayerNote {
  id: number;
  playerId: number;
  adminId: number;
  text?: string;
  date: string;
  isBan: boolean;
  banTime?: number;
  isConfidential: boolean;
  adminRank: string;
  noteCategory?: number;
  roundId?: number;
  notedPlayerCkey?: string;
  notingAdminCkey?: string;
}

const UserNotesModal = (props: { player: Player }) => {
  const { player } = props;

  const { notes } = player;

  return (
    <div className="flex flex-col">
      <div className="flex flex-row gap-3">
        <div className="text-2xl">Notes:</div>
        <div className="flex flex-col justify-center">
          <div className="flex flex-row gap-1">
            <AddNote player={player} />
            |
            <ViewAppliedNotes player={player} />
          </div>
        </div>
      </div>
      <NotesList notes={notes} />
    </div>
  );
};

const NotesList = (props: { notes?: PlayerNote[]; displayNoted?: boolean }) => {
  const { notes, displayNoted } = props;

  return (
    <div className="border-[#3f3f3f] border-2 p-3 flex flex-col gap-3 h-96 overflow-auto">
      {notes
        ?.filter((note) => note.text)
        .map((note) => (
          <UserNote note={note} key={note.id} displayNoted={displayNoted} />
        ))}
      {!notes ||
        (!notes.length && (
          <div className="flex flex-row justify-center">No notes..</div>
        ))}
    </div>
  );
};

const ViewAppliedNotes = (props: { player: Player }) => {
  const [notes, setNotes] = useState<PlayerNote[] | null>();

  const { player } = props;

  const openDialog = () => {
    callApi(`/User/${player.id}/AppliedNotes`).then((val) =>
      val.json().then((json) => setNotes(json))
    );
  };

  return (
    <>
      <LinkColor onClick={() => openDialog()}>View Applied Notes</LinkColor>
      {notes && (
        <Dialog open={!!notes} toggle={() => setNotes(null)}>
          <div className="pt-10">
            <NotesList notes={notes} displayNoted={true} />
          </div>
        </Dialog>
      )}
    </>
  );
};

const AddNote = (props: { player: Player }) => {
  const [adding, setAdding] = useState(false);

  const [message, setMessage] = useState("");
  const [confidential, setConfidential] = useState(false);

  const [confirm, setConfirm] = useState(false);

  const { player } = props;

  const { ckey } = player;

  const global = useContext(GlobalContext);
  const refetch = useContext(ActiveLookupContext);

  const send = () => {
    callApi(`/User/${player.id}/Note`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        message: message,
        category: "1",
        confidential: confidential ? "true" : "false",
      }),
    }).then((response) => {
      refetch?.updateUser({ userCkey: ckey });
      setAdding(false);
      if (response.status === 202) {
        global?.updateAndShowToast(`Added note to ${ckey}.`);
      } else {
        global?.updateAndShowToast(`Failed to add note.`);
      }
    });
  };

  return (
    <>
      <LinkColor onClick={() => setAdding(true)}>Add Note</LinkColor>
      {adding && (
        <Dialog toggle={() => setAdding(false)} open={adding}>
          <form className="pt-10">
            <div className="flex flex-col gap-3">
              <div className="flex flex-col lg:flex-row justify-center gap-3">
                <div className="flex flex-col">
                  <label
                    className="flex flex-row justify-center"
                    htmlFor="message"
                  >
                    Message
                  </label>
                  <textarea
                    id="message"
                    className="max-w-full box-border"
                    cols={70}
                    rows={5}
                    onChange={(event) => {
                      setMessage(event.target.value);
                    }}
                  />
                </div>
                <div className="flex flex-col">
                  <label
                    className="flex flex-row justify-center"
                    htmlFor="confidential"
                  >
                    Confidential
                  </label>
                  <input
                    id="confidential"
                    type="checkbox"
                    onChange={() => setConfidential(!confidential)}
                  />
                </div>
              </div>
              <div className="flex flex-row justify-center">
                {!confirm ? (
                  <LinkColor onClick={() => setConfirm(true)}>Submit</LinkColor>
                ) : (
                  <LinkColor onClick={() => send()} className="text-red-700">
                    Confirm
                  </LinkColor>
                )}
              </div>
            </div>
          </form>
        </Dialog>
      )}
    </>
  );
};

const NOTE_MERIT = 2;
const NOTE_WHITELIST = 3;

const UserNote = (props: { note: PlayerNote; displayNoted?: boolean }) => {
  const { note, displayNoted } = props;
  const {
    text,
    date,
    isConfidential,
    adminRank,
    isBan,
    banTime,
    noteCategory,
    notedPlayerCkey,
    notingAdminCkey,
    roundId,
  } = note;

  let tag = <ColoredText color="#008800">[ADMIN]</ColoredText>;

  switch (noteCategory) {
    case NOTE_MERIT:
      tag = <ColoredText color="#9e3dff">[MERIT]</ColoredText>;
      break;
    case NOTE_WHITELIST:
      tag = <ColoredText color="#324da5">[WHITELIST]</ColoredText>;
      break;
  }

  if (isBan) {
    tag = <ColoredText color="#880000">[BAN]</ColoredText>;
  }

  return (
    <div className="flex flex-col">
      <div className="flex flex-col md:flex-row gap-1">
        {tag}
        <div className="text-wrap">
          {isBan && banTime ? `Banned for ${banTime}: ` : ""}
          {text}
        </div>
      </div>
      <div className="italic flex flex-row justify-end gap-1">
        {displayNoted && (
          <div>
            to
            <NameExpand name={notedPlayerCkey} />
          </div>
        )}
        {"by"}
        <NameExpand name={notingAdminCkey} /> ({adminRank})
        {!!isConfidential && "[CONFIDENTIALLY]"} on {date}
        {roundId ? ` (#${roundId})` : ""}
      </div>
    </div>
  );
};

interface ColoredTextType extends PropsWithChildren {
  color: string;
}

const ColoredText = (props: ColoredTextType) => {
  return <div style={{ color: props.color }}>{props.children}</div>;
};

interface PlayerJobBan {
  id: number;
  playerId: number;
  adminId: number;
  text: string;
  date: string;
  banTime?: number;
  expiration?: number;
  role: string;
  banningAdminCkey?: string;
}

const UserJobBansModal = (props: { player: Player }) => {
  const { player } = props;

  const { jobBans } = player;

  return (
    <div className="flex flex-col">
      <div className="text-2xl">Job Bans:</div>
      <div className="border-[#3f3f3f] border-2 p-3 flex flex-col gap-3">
        {jobBans?.map((jobBan) => (
          <JobBan jobBan={jobBan} key={jobBan.id} />
        ))}
        {!jobBans?.length && (
          <div className="flex flex-row justify-center">No job bans.</div>
        )}
      </div>
    </div>
  );
};

const JobBan = (props: { jobBan: PlayerJobBan }) => {
  const { text, banningAdminCkey, date, role } = props.jobBan;

  return (
    <div className="flex flex-col">
      <div>
        {role.toUpperCase()} - {text}
      </div>
      <div className="flex flex-row justify-end italic">
        by {banningAdminCkey} on {date}
      </div>
    </div>
  );
};

interface KnownAltsResponse {
  mainAccount: string | null;
  alts: string[];
}

const KnownAltsModal = (props: { player: Player }) => {
  const { player } = props;
  const [altsData, setAltsData] = useState<KnownAltsResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [newAltCkey, setNewAltCkey] = useState("");
  const global = useContext(GlobalContext);

  const fetchAlts = useCallback(() => {
    if (!player.ckey) return;

    setLoading(true);
    callApi(`/User/KnownAlts?ckey=${player.ckey}`)
      .then((response) => response.json())
      .then((json: KnownAltsResponse) => {
        setAltsData(json);
      })
      .catch((err) => {
        console.error("Failed to fetch known alts:", err);
        setAltsData({ mainAccount: null, alts: [] });
      })
      .finally(() => {
        setLoading(false);
      });
  }, [player.ckey]);

  useEffect(() => {
    fetchAlts();
  }, [fetchAlts]);

  const addAlt = useCallback(() => {
    if (!player.ckey || !newAltCkey.trim()) return;

    const playerCkey = altsData?.mainAccount || player.ckey;
    const altCkey = newAltCkey.trim().toLowerCase().replace(/[^a-z0-9@]/g, "");

    callApi("/User/KnownAlts", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ playerCkey, altCkey }),
    })
      .then((response) => {
        if (response.ok) {
          setNewAltCkey("");
          fetchAlts();
          global?.updateAndShowToast("Alt added.");
        } else {
          global?.updateAndShowToast("Failed to add alt.");
        }
      })
      .catch(() => {
        global?.updateAndShowToast("Failed to add alt.");
      });
  }, [player.ckey, newAltCkey, altsData, fetchAlts, global]);

  const removeAlt = useCallback(
    (altCkey: string) => {
      if (!player.ckey) return;

      const playerCkey = altsData?.mainAccount || player.ckey;

      callApi("/User/KnownAlts", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ playerCkey, altCkey }),
      })
        .then((response) => {
          if (response.ok) {
            fetchAlts();
            global?.updateAndShowToast("Alt removed.");
          } else {
            global?.updateAndShowToast("Failed to remove alt.");
          }
        })
        .catch(() => {
          global?.updateAndShowToast("Failed to remove alt.");
        });
    },
    [player.ckey, altsData, fetchAlts, global]
  );

  const hasAlts = altsData && (altsData.mainAccount || altsData.alts.length > 0);

  return (
    <div className="flex flex-col">
      <div className="text-2xl">Known Alts:</div>
      <div className="border-[#3f3f3f] border-2 p-3 flex flex-col gap-3">
        {loading && <div className="text-gray-400">Loading...</div>}
        {!loading && !hasAlts && (
          <div className="flex flex-row justify-center">No known alts.</div>
        )}
        {!loading && altsData?.mainAccount && (
          <div className="flex flex-col">
            <div className="text-yellow-400">This is an alt account of:</div>
            <div className="ml-4">
              <NameExpand name={altsData.mainAccount} />
            </div>
          </div>
        )}
        {!loading && altsData && altsData.alts.length > 0 && (
          <div className="flex flex-col">
            <div className="text-yellow-400">Known alt accounts:</div>
            <div className="ml-4 flex flex-col gap-1">
              {altsData.alts.map((alt) => (
                <div key={alt} className="flex flex-row items-center gap-2">
                  <NameExpand name={alt} />
                  <button
                    type="button"
                    className="text-red-400 hover:text-red-300 text-sm font-bold"
                    onClick={() => removeAlt(alt)}
                    title="Remove alt"
                  >
                    X
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}
        {!loading && (
          <div className="flex flex-row gap-2 items-center mt-2">
            <input
              type="text"
              placeholder="Alt ckey"
              value={newAltCkey}
              onChange={(e) => setNewAltCkey(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && addAlt()}
              className="bg-[#2a2a2a] border border-[#3f3f3f] px-2 py-1 text-sm"
            />
            <button
              type="button"
              className="bg-[#3f3f3f] hover:bg-[#4f4f4f] px-2 py-1 text-sm"
              onClick={addAlt}
            >
              Add Alt
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
