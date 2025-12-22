export type Ticket = {
	id: number;
	ticket: number;
	action: string;
	message: string;
	recipient: string;
	sender: string;
	roundId?: number;
	time: string;
	urgent: boolean;
};

export type TicketLoader = {
	round: string;
	ticketNum: string;
};
