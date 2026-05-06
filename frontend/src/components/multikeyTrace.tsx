import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useLoaderData, useNavigate } from "react-router-dom";
import ForceGraph from "react-force-graph-2d";
import type { ForceGraphMethods } from "react-force-graph-2d";
import { callApi } from "../helpers/api";
import type { CkeyLink, MultiKeyTrace as MultiKeyTraceType } from "../types/loginTriplet";
import { DetailedCid } from "./detailedCid";
import { DetailedIp } from "./detailedIp";
import { NameExpand } from "./nameExpand";

type ViewMode = "list" | "graph";

function LinkEvidence({ link }: { link: CkeyLink }) {
	return (
		<div className="flex flex-wrap gap-2 text-sm">
			{link.sharedCids.length > 0 && (
				<div className="flex flex-wrap items-center gap-1">
					<span className="text-gray-500">CID:</span>
					{link.sharedCids.map((cid) => (
						<DetailedCid key={cid} cid={cid} />
					))}
				</div>
			)}
			{link.sharedIps.length > 0 && (
				<div className="flex flex-wrap items-center gap-1">
					<span className="text-gray-500">IP:</span>
					{link.sharedIps.map((ip) => (
						<DetailedIp key={ip} ip={ip} />
					))}
				</div>
			)}
			{link.sharedHwids.length > 0 && (
				<div className="flex flex-wrap items-center gap-1">
					<span className="text-gray-500">HWID:</span>
					{link.sharedHwids.map((hwid) => (
						<span key={hwid} className="text-yellow-400">{hwid}</span>
					))}
				</div>
			)}
		</div>
	);
}

type GraphNode = { id: string; isRoot: boolean; x?: number; y?: number };
type GraphLink = { source: string; target: string; score: number; label: string };

function TraceGraph({
	traceData,
	onNodeClick,
}: {
	traceData: MultiKeyTraceType;
	onNodeClick: (ckey: string) => void;
}) {
	const containerRef = useRef<HTMLDivElement>(null);
	const fgRef = useRef<ForceGraphMethods<GraphNode, GraphLink>>();
	const [dimensions, setDimensions] = useState({ width: 800, height: 600 });

	useEffect(() => {
		const el = containerRef.current;
		if (!el) return;
		const obs = new ResizeObserver((entries) => {
			const { width, height } = entries[0].contentRect;
			setDimensions({ width, height });
		});
		obs.observe(el);
		return () => obs.disconnect();
	}, []);

	useEffect(() => {
		if (fgRef.current) {
			fgRef.current.centerAt(0, 0, 0);
			fgRef.current.zoom(1, 0);
		}
	}, [traceData]);

	const graphData = useMemo(() => {
		const nodes: GraphNode[] = [
			{ id: traceData.rootCkey, isRoot: true },
			...traceData.connectedCkeys.map((c) => ({ id: c, isRoot: false })),
		];

		const links: GraphLink[] = traceData.links.map((link) => {
			const score = link.sharedCids.length + link.sharedIps.length + link.sharedHwids.length;
			const parts: string[] = [];
			if (link.sharedCids.length) parts.push(`${link.sharedCids.length} CID`);
			if (link.sharedIps.length) parts.push(`${link.sharedIps.length} IP`);
			if (link.sharedHwids.length) parts.push(`${link.sharedHwids.length} HWID`);
			return {
				source: link.ckeyA,
				target: link.ckeyB,
				score,
				label: parts.join(", "),
			};
		});

		return { nodes, links };
	}, [traceData]);

	const nodeCanvasObject = useCallback(
		(node: GraphNode, ctx: CanvasRenderingContext2D, globalScale: number) => {
			const label = node.id;
			const fontSize = 12 / globalScale;
			ctx.font = `${fontSize}px JetBrains Mono, monospace`;

			ctx.fillStyle = node.isRoot ? "#f59e0b" : "#9ca3af";
			ctx.beginPath();
			ctx.arc(node.x!, node.y!, node.isRoot ? 5 : 3, 0, 2 * Math.PI);
			ctx.fill();

			ctx.fillStyle = node.isRoot ? "#f59e0b" : "#d1d5db";
			ctx.textAlign = "center";
			ctx.textBaseline = "top";
			ctx.fillText(label, node.x!, node.y! + (node.isRoot ? 7 : 5));
		},
		[],
	);

	const linkColor = useCallback((link: GraphLink) => {
		if (link.score >= 5) return "#ef4444";
		if (link.score >= 3) return "#f59e0b";
		return "#4b5563";
	}, []);

	const linkWidth = useCallback((link: GraphLink) => {
		return Math.min(link.score * 0.8, 5);
	}, []);

	return (
		<div ref={containerRef} className="border border-[#3f3f3f] w-full" style={{ height: "600px" }}>
			<ForceGraph
				ref={fgRef}
				graphData={graphData}
				width={dimensions.width}
				height={dimensions.height}
				backgroundColor="#1a1a1a"
				nodeCanvasObject={nodeCanvasObject}
				nodePointerAreaPaint={(node: GraphNode, color: string, ctx: CanvasRenderingContext2D) => {
					ctx.fillStyle = color;
					ctx.beginPath();
					ctx.arc(node.x!, node.y!, 8, 0, 2 * Math.PI);
					ctx.fill();
				}}
				linkColor={linkColor}
				linkWidth={linkWidth}
				linkLabel={(link: GraphLink) => link.label}
				onNodeClick={(node: GraphNode) => onNodeClick(node.id)}
				cooldownTicks={100}
				onEngineStop={() => {
					if (fgRef.current) {
						fgRef.current.zoomToFit(400, 60);
					}
				}}
				enableZoomInteraction={true}
				enablePanInteraction={true}
			/>
		</div>
	);
}

export const MultikeyTrace: React.FC = () => {
	const loaderCkey = useLoaderData() as string;
	const navigate = useNavigate();
	const [ckey, setCkey] = useState(loaderCkey || "");
	const [maxDepth, setMaxDepth] = useState(3);
	const [loading, setLoading] = useState(false);
	const [traceData, setTraceData] = useState<MultiKeyTraceType | null>(null);
	const [viewMode, setViewMode] = useState<ViewMode>("graph");

	const runTrace = async (targetCkey: string) => {
		if (!targetCkey.trim()) return;
		setLoading(true);
		setTraceData(null);
		try {
			const res = await callApi(
				`/Connections/Trace?ckey=${encodeURIComponent(targetCkey.trim())}&max_depth=${maxDepth}`,
			);
			if (res.ok) {
				setTraceData(await res.json());
			}
		} finally {
			setLoading(false);
		}
	};

	useEffect(() => {
		if (loaderCkey) {
			setCkey(loaderCkey);
			runTrace(loaderCkey);
		}
	}, [loaderCkey]);

	const handleSubmit = (e: React.FormEvent) => {
		e.preventDefault();
		const trimmed = ckey.trim();
		if (!trimmed) return;
		navigate(`/multikey/${trimmed}`, { replace: true });
		runTrace(trimmed);
	};

	const getLinksForCkey = (targetCkey: string): CkeyLink[] => {
		if (!traceData) return [];
		return traceData.links.filter(
			(link) => link.ckeyA === targetCkey || link.ckeyB === targetCkey,
		);
	};

	const linkScore = (targetCkey: string): number => {
		const links = getLinksForCkey(targetCkey);
		let score = 0;
		for (const link of links) {
			score += link.sharedCids.length + link.sharedIps.length + link.sharedHwids.length;
		}
		return score;
	};

	const sortedCkeys = traceData
		? [...traceData.connectedCkeys].sort((a, b) => linkScore(b) - linkScore(a))
		: [];

	return (
		<div className="flex flex-col gap-3 p-3">
			<form onSubmit={handleSubmit} className="flex flex-row gap-2 items-end">
				<div className="flex flex-col">
					<label htmlFor="trace-ckey" className="text-gray-400 text-sm">
						Ckey
					</label>
					<input
						type="text"
						id="trace-ckey"
						value={ckey}
						onInput={(e) => setCkey((e.target as HTMLInputElement).value)}
						className="px-2 py-1 foreground border border-[#3f3f3f]"
						placeholder="Enter ckey..."
					/>
				</div>
				<div className="flex flex-col">
					<label htmlFor="trace-depth" className="text-gray-400 text-sm">
						Depth
					</label>
					<select
						id="trace-depth"
						value={maxDepth}
						onChange={(e) => setMaxDepth(Number(e.target.value))}
						className="px-2 py-1 foreground border border-[#3f3f3f]"
					>
						{[1, 2, 3, 4, 5].map((d) => (
							<option key={d} value={d}>
								{d}
							</option>
						))}
					</select>
				</div>
				<button
					type="submit"
					className="px-3 py-1 foreground border border-[#3f3f3f] hover:bg-gray-700 text-gray-300"
				>
					Trace
				</button>
			</form>

			{loading && <div className="text-gray-400">Tracing connections...</div>}

			{traceData && (
				<div className="flex flex-col gap-3">
					<div className="flex flex-row gap-3 items-center text-sm text-gray-400">
						<span>
							Root: <span className="text-white">{traceData.rootCkey}</span>
						</span>
						<span>
							Connected accounts:{" "}
							<span className="text-white">{traceData.connectedCkeys.length}</span>
						</span>
						<span>
							Depth: <span className="text-white">{traceData.depthReached}</span>
						</span>
						<span className="text-gray-600">|</span>
						<button
							type="button"
							onClick={() => setViewMode("graph")}
							className={`hover:text-white ${viewMode === "graph" ? "text-white underline" : ""}`}
						>
							Graph
						</button>
						<button
							type="button"
							onClick={() => setViewMode("list")}
							className={`hover:text-white ${viewMode === "list" ? "text-white underline" : ""}`}
						>
							List
						</button>
					</div>

					{traceData.truncated && (
						<div className="text-yellow-400 text-sm border border-yellow-400/30 p-2">
							Results truncated — too many connected accounts. Try reducing depth.
						</div>
					)}

					{sortedCkeys.length === 0 && (
						<div className="text-gray-500">No connected accounts found.</div>
					)}

					{sortedCkeys.length > 0 && viewMode === "graph" && (
						<TraceGraph
							traceData={traceData}
							onNodeClick={(clickedCkey) => navigate(`/multikey/${clickedCkey}`)}
						/>
					)}

					{sortedCkeys.length > 0 && viewMode === "list" && (
						<div className="flex flex-col border border-[#3f3f3f] p-3 gap-2 max-h-[700px] overflow-auto">
							{sortedCkeys.map((connectedCkey) => {
								const links = getLinksForCkey(connectedCkey);
								return (
									<div
										key={connectedCkey}
										className="flex flex-col gap-1 p-2 border-b border-[#3f3f3f] last:border-b-0"
									>
										<NameExpand name={connectedCkey} />
										{links.map((link) => {
											const otherCkey =
												link.ckeyA === connectedCkey ? link.ckeyB : link.ckeyA;
											return (
												<div key={`${link.ckeyA}-${link.ckeyB}`} className="pl-4">
													<span className="text-gray-500 text-sm mr-2">
														via {otherCkey === traceData.rootCkey ? "root" : otherCkey}:
													</span>
													<LinkEvidence link={link} />
												</div>
											);
										})}
									</div>
								);
							})}
						</div>
					)}
				</div>
			)}
		</div>
	);
};
