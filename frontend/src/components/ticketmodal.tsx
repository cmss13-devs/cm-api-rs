import React, { useEffect, useState } from "react";
import { Link, useLoaderData, useNavigate } from "react-router-dom";
import { Ticket, TicketLoader } from "../types/ticket";
import { LinkColor } from "./link";
import { NameExpand } from "./nameExpand";
import { Dialog } from "./dialog";

type TicketModalType = {
	round?: number;
	tickets: Ticket[];
};

export const TicketModal: React.FC<TicketModalType> = (
	props: TicketModalType,
) => {
	const { tickets, round } = props;

	const [ticket, setTicket] = useState<
		{ ticketNum: number; round?: number } | undefined
	>();

	const { ticketNum } = useLoaderData() as TicketLoader;

	useEffect(() => {
		if (ticketNum && !ticket) {
			setTicket({ ticketNum: parseInt(ticketNum) });
		}
		if (!ticketNum && ticket && round) {
			setTicket(undefined);
		}
	}, [ticket, ticketNum, setTicket, round]);

	const nav = useNavigate();

	const distinctNums: string[] = [];
	let distinctTickets: Ticket[] = [];
	tickets.forEach((ticket) => {
		if (distinctNums.includes(`${ticket.roundId}-${ticket.ticket}`)) return;
		distinctNums.push(`${ticket.roundId}-${ticket.ticket}`);
		distinctTickets.push(ticket);
	});

	if (!round) {
		distinctTickets = distinctTickets.reverse();
	}

	return (
		<div className="border p-2 rounded border-[#3f3f3f] shadow-lg">
			{round && (
				<div className="flex flex-row justify-center text-xl">
					Round {round}
				</div>
			)}
			<div className="flex flex-col pt-3 gap-2">
				{distinctTickets.map((ticket) => (
					<div key={ticket.id} className="border-t pt-1 border-[#3f3f3f]">
						<LinkColor
							onClick={() => {
								if (round) nav(`/ticket/${ticket.roundId}/${ticket.ticket}`);
								else {
									setTicket({
										ticketNum: ticket.ticket,
										round: ticket.roundId,
									});
								}
							}}
						>
							{!round && `#${ticket.roundId} `}Ticket #{ticket.ticket}
						</LinkColor>
						: <NameExpand name={ticket.sender} />
						{ticket.recipient && (
							<>
								{" -> "}
								<NameExpand name={ticket.recipient} />
							</>
						)}
						{" -"} {ticket.message}
						{!round && (
							<span className="float-end">
								{new Date(Date.parse(ticket.time)).toLocaleString()}
							</span>
						)}
					</div>
				))}
			</div>
			{ticket && (
				<Dialog
					open={!!ticket}
					toggle={() => {
						if (round) nav("..", { relative: "path" });
						else setTicket(undefined);
					}}
					className="max-h-[80%]"
				>
					<TicketDetail
						tickets={tickets}
						ticket={ticket.ticketNum}
						round={ticket.round}
					/>
				</Dialog>
			)}
		</div>
	);
};

const TicketDetail = (props: {
	tickets: Ticket[];
	ticket: number;
	round?: number;
}) => {
	const { tickets, ticket, round } = props;

	const relevantTickets = tickets.filter(
		(tick) => tick.ticket == ticket && (round ? tick.roundId == round : true),
	);

	return (
		<div className="flex flex-col pt-7 gap-2">
			<div className="flex flex-row justify-center">
				{round && (
					<LinkColor>
						<Link to={`/ticket/${round}`}>Round {round}</Link>
					</LinkColor>
				)}
			</div>
			{relevantTickets.map((ticket) => (
				<div key={ticket.id}>
					<div className="flex flex-row justify-between border-b pt-1 border-[#555555]">
						<div>
							<NameExpand name={ticket.sender} />
							{ticket.recipient && (
								<>
									{" -> "}
									<NameExpand name={ticket.recipient} />
								</>
							)}
						</div>
						<div>{new Date(Date.parse(ticket.time)).toLocaleString()}</div>
					</div>
					<div>{ticket.message}</div>
				</div>
			))}
		</div>
	);
};
