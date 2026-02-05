import type React from "react";
import type { PropsWithChildren } from "react";
import { useRef, useState } from "react";
import { Link, Navigate } from "react-router-dom";
import { AuthentikLookup } from "./authentikLookup";
import { CidLookup } from "./cidLookup";
import { Dialog } from "./dialog";
import { IpLookup } from "./ipLookup";
import { RoundData } from "./roundData";
import { LookupMenu } from "./userLookup";

export default function HomePage(): React.ReactElement {
  return (
    <div className="md:flex flex-row justify-center">
      <div className="flex flex-col gap-3">
        <div className="flex flex-row justify-between">
          <div className="text-3xl underline text-center">[cmdb]</div>
        </div>

        <div className="flex flex-col md:flex-row gap-3">
          <LookupOption type="lookup">Lookup User</LookupOption>
          <LookupOption type="ip">Lookup IP</LookupOption>
          <LookupOption type="cid">Lookup CID</LookupOption>
          <LookupOption type="discordId">Lookup Discord</LookupOption>
          <LookupOption type="authentikUuid">Lookup Authentik</LookupOption>
        </div>

        <Link
          to={"/sticky"}
          className={
            "border border-[#3f3f3f] rounded p-3 cursor-pointer grow clicky shadow-lg"
          }
        >
          Sticky Menu
        </Link>
        <Link
          to={"/ticket"}
          className="border border-[#555555] rounded p-3 cursor-pointer grow clicky"
        >
          Ticket Menu
        </Link>
        <Link
          to={"/whitelists"}
          className="border border-[#555555] rounded p-3 cursor-pointer grow clicky"
        >
          Whitelist Menu
        </Link>
        <Link
          to={"/new_players"}
          className="border border-[#555555] rounded p-3 cursor-pointer grow clicky"
        >
          New Players
        </Link>

        <RoundData />
      </div>
    </div>
  );
}

interface LookupProps extends PropsWithChildren {
  type: "lookup" | "ip" | "cid" | "discordId" | "authentikUuid";
}

const LookupOption = (props: LookupProps) => {
  const [selected, setSelected] = useState(false);
  const [value, setValue] = useState<string | null>(null);
  const [heldValue, setHeldValue] = useState<string | null>(null);
  const [timer, setTimer] = useState<number>(0);

  const { type } = props;

  const inputRef = useRef<HTMLInputElement>(null);

  const close = () => setValue(null);

  return (
    <>
      <button
        type="button"
        className="border border-[#3f3f3f] p-3 cursor-pointer grow clicky rounded text-left"
        onClick={() => {
          setSelected(true);
          clearTimeout(timer);
          const timeout = setTimeout(() => {
            setSelected(false);
          }, 6000);
          setTimeout(() => {
            inputRef.current?.focus();
          }, 1);
          setTimer(timeout);
        }}
      >
        {selected && (
          <form
            className="flex flex-row justify-center gap-3"
            onSubmit={(event) => {
              event.preventDefault();
              setValue(heldValue);
            }}
          >
            <input
              type="text"
              value={heldValue ?? ""}
              ref={inputRef}
              onInput={(event) => {
                const target = event.target as HTMLInputElement;
                setHeldValue(target.value);
                clearTimeout(timer);
                setTimer(
                  setTimeout(() => {
                    setSelected(false);
                  }, 10000)
                );
              }}
            ></input>
          </form>
        )}
        {!selected && props.children}
      </button>
      {value && (
        <Dialog
          open={!!value}
          toggle={() => setValue(null)}
          className="md:w-11/12 md:h-11/12"
        >
          {type === "lookup" && <Navigate to={`/user/${value}`} />}
          {type === "discordId" && (
            <LookupMenu discordId={value} close={close} />
          )}
          {type === "cid" && <CidLookup initialCid={value} close={close} />}
          {type === "ip" && <IpLookup initialIp={value} close={close} />}
          {type === "authentikUuid" && (
            <AuthentikLookup initialUuid={value} close={close} />
          )}
        </Dialog>
      )}
    </>
  );
};
