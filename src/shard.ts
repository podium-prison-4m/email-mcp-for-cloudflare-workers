// Master/slave sharding.
//
// One deployment of this codebase can run as a "slave": it stores a subset of
// the mail accounts in its own KV, exposes no sign-in, admin UI, or OAuth
// routes, and serves its MCP endpoint only to the master deployment, which
// authenticates with a shared internal key (X-Internal-Key header). The
// master keeps the public entry point (Cloudflare Access, admin login, OAuth
// callbacks) and forwards tool calls for slave-held accounts to the slave,
// merging aggregate results so clients only ever talk to the master.
//
// Configuration (Worker vars / secrets):
//   ROLE               "slave" for a slave deployment; anything else = master.
//   INTERNAL_API_KEY   Secret. Required on a slave: the key it accepts.
//   SLAVE_MCP_URL      Master only: the slave's /mcp URL, e.g.
//                      https://email-mcp-slave.<subdomain>.workers.dev/mcp
//   SLAVE_INTERNAL_KEY Master only, secret: the key the slave accepts.

export interface ShardConfig {
	role: string;
	internalKey?: string;
	slaveUrl?: string;
	slaveKey?: string;
}

export function shardConfig(env: unknown): ShardConfig {
	const vars = (env ?? {}) as Record<string, unknown>;
	const str = (name: string) =>
		typeof vars[name] === "string" && vars[name] ? (vars[name] as string) : undefined;
	return {
		role: str("ROLE") ?? "master",
		internalKey: str("INTERNAL_API_KEY"),
		slaveUrl: str("SLAVE_MCP_URL"),
		slaveKey: str("SLAVE_INTERNAL_KEY"),
	};
}

export function isSlave(config: ShardConfig): boolean {
	return config.role === "slave";
}

export function hasSlave(config: ShardConfig): boolean {
	return Boolean(config.slaveUrl && config.slaveKey);
}

// Constant-time string comparison (lengths are compared first; key length is
// not treated as secret beyond what timing already reveals).
export function timingSafeEqual(a: string, b: string): boolean {
	const encoder = new TextEncoder();
	const left = encoder.encode(a);
	const right = encoder.encode(b);
	if (left.length !== right.length) return false;
	let diff = 0;
	for (let i = 0; i < left.length; i++) diff |= left[i] ^ right[i];
	return diff === 0;
}

export function slaveRequestAuthorized(request: Request, config: ShardConfig): boolean {
	if (!config.internalKey) return false;
	const presented = request.headers.get("X-Internal-Key");
	return presented !== null && timingSafeEqual(presented, config.internalKey);
}

export interface McpToolResult {
	content?: unknown;
	structuredContent?: Record<string, unknown>;
	isError?: boolean;
	[key: string]: unknown;
}

// Minimal MCP client for master -> slave forwarding: one short-lived session
// per call (initialize, initialized notification, tools/call), mirroring the
// transport contract of the MCP endpoint without any client state.
export class ShardClient {
	private url: string;
	private key: string;
	private fetchFn: typeof fetch;

	constructor(url: string, key: string, fetchFn: typeof fetch = (input, init) => fetch(input, init)) {
		this.url = url;
		this.key = key;
		this.fetchFn = fetchFn;
	}

	private async post(
		payload: unknown,
		session?: string,
	): Promise<{ body: any; session?: string }> {
		const headers: Record<string, string> = {
			"Content-Type": "application/json",
			Accept: "application/json, text/event-stream",
			"X-Internal-Key": this.key,
		};
		if (session) headers["Mcp-Session-Id"] = session;
		const response = await this.fetchFn(this.url, {
			method: "POST",
			headers,
			body: JSON.stringify(payload),
		});
		const newSession = response.headers.get("Mcp-Session-Id") ?? session;
		const raw = await response.text();
		if (!response.ok) throw new Error(`Slave MCP request failed (${response.status})`);
		if (!raw) return { body: undefined, session: newSession };
		// The endpoint answers either plain JSON or an SSE stream with data: lines.
		let parsed: any;
		if (raw.includes("data:")) {
			for (const line of raw.split(/\r?\n/)) {
				if (line.startsWith("data:")) parsed = JSON.parse(line.slice(5).trim());
			}
			if (parsed === undefined) throw new Error("Slave MCP returned an unreadable SSE response");
		} else {
			parsed = JSON.parse(raw);
		}
		return { body: parsed, session: newSession };
	}

	async callTool(name: string, args: Record<string, unknown>): Promise<McpToolResult> {
		const init = await this.post({
			jsonrpc: "2.0",
			id: 1,
			method: "initialize",
			params: {
				protocolVersion: "2025-03-26",
				capabilities: {},
				clientInfo: { name: "email-mcp-master", version: "1.0" },
			},
		});
		if (init.body?.error) throw new Error(`Slave MCP initialize failed: ${init.body.error.message ?? "unknown error"}`);
		const session = init.session;
		try {
			await this.post({ jsonrpc: "2.0", method: "notifications/initialized" }, session);
		} catch {
			// The notification has no response to consume; ignore transport noise.
		}
		const result = await this.post(
			{ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name, arguments: args } },
			session,
		);
		if (result.body?.error)
			throw new Error(`Slave MCP call failed: ${result.body.error.message ?? "unknown error"}`);
		return (result.body?.result ?? {}) as McpToolResult;
	}

	async listAccounts(): Promise<Array<Record<string, unknown>>> {
		const result = await this.callTool("email_list_accounts", {});
		const accounts = result.structuredContent?.accounts;
		return Array.isArray(accounts) ? (accounts as Array<Record<string, unknown>>) : [];
	}
}

// Merge two aggregate tool results (local + slave): arrays are concatenated,
// numeric counters are summed, and every other field keeps the local value.
// Used for email_list_accounts and the all-account tools so a client of the
// master sees one combined answer.
export function mergeStructured(
	local: Record<string, unknown>,
	remote: Record<string, unknown>,
): Record<string, unknown> {
	const merged: Record<string, unknown> = { ...local };
	for (const [key, remoteValue] of Object.entries(remote)) {
		const localValue = merged[key];
		if (Array.isArray(localValue) && Array.isArray(remoteValue)) {
			merged[key] = [...localValue, ...remoteValue];
		} else if (typeof localValue === "number" && typeof remoteValue === "number") {
			merged[key] = localValue + remoteValue;
		} else if (localValue === undefined) {
			merged[key] = remoteValue;
		}
	}
	return merged;
}

export function toolResultFromStructured(structured: Record<string, unknown>): McpToolResult {
	return {
		content: [{ type: "text", text: JSON.stringify(structured, null, 2) }],
		structuredContent: structured,
	};
}

// --- Account provisioning between master and slave -------------------------
//
// OAuth sign-in and account creation happen on the master (Plan A). To store
// the resulting account on a slave, the master pushes the complete account
// record (credentials included) server-to-server to the slave's internal
// import endpoint; the slave encrypts it with its own key. Records keep
// their IDs so watermarks and client references survive the move.

export async function handleSlaveImport(
	request: Request,
	store: { importAccounts: (accounts: never[]) => Promise<number> },
): Promise<Response> {
	let payload: { accounts?: unknown };
	try {
		payload = (await request.json()) as { accounts?: unknown };
	} catch {
		return Response.json({ error: "Invalid JSON body" }, { status: 400 });
	}
	if (!Array.isArray(payload.accounts) || payload.accounts.length === 0)
		return Response.json({ error: "accounts must be a non-empty array" }, { status: 400 });
	for (const account of payload.accounts as Array<Record<string, unknown>>) {
		if (
			!account ||
			typeof account.id !== "string" ||
			typeof account.email !== "string" ||
			typeof (account as { imap?: unknown }).imap !== "object" ||
			typeof (account as { auth?: unknown }).auth !== "object"
		)
			return Response.json({ error: "Malformed account record" }, { status: 400 });
	}
	const imported = await store.importAccounts(payload.accounts as never[]);
	return Response.json({ imported });
}

export async function pushAccountsToSlave(
	config: ShardConfig,
	accounts: unknown[],
	fetchFn: typeof fetch = (input, init) => fetch(input, init),
): Promise<number> {
	if (!hasSlave(config)) throw new Error("No slave deployment is configured");
	const origin = new URL(config.slaveUrl!).origin;
	const response = await fetchFn(`${origin}/internal/import-accounts`, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			"X-Internal-Key": config.slaveKey!,
		},
		body: JSON.stringify({ accounts }),
	});
	if (!response.ok)
		throw new Error(`Slave import failed (${response.status}): ${(await response.text()).slice(0, 200)}`);
	const body = (await response.json()) as { imported?: number };
	return body.imported ?? accounts.length;
}
