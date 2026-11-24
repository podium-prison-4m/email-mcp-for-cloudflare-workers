import assert from "node:assert/strict";
import test from "node:test";
import {
	ShardClient,
	mergeStructured,
	shardConfig,
	slaveRequestAuthorized,
	timingSafeEqual,
} from "../src/shard.ts";

test("timingSafeEqual compares values without early exit semantics", () => {
	assert.equal(timingSafeEqual("secret-key", "secret-key"), true);
	assert.equal(timingSafeEqual("secret-key", "secret-kez"), false);
	assert.equal(timingSafeEqual("short", "shorter"), false);
});

test("slave authorization requires the configured internal key", () => {
	const config = shardConfig({ ROLE: "slave", INTERNAL_API_KEY: "topsecret" });
	assert.equal(config.role, "slave");
	const ok = new Request("https://slave.example/mcp", {
		headers: { "X-Internal-Key": "topsecret" },
	});
	const wrong = new Request("https://slave.example/mcp", {
		headers: { "X-Internal-Key": "nope" },
	});
	const missing = new Request("https://slave.example/mcp");
	assert.equal(slaveRequestAuthorized(ok, config), true);
	assert.equal(slaveRequestAuthorized(wrong, config), false);
	assert.equal(slaveRequestAuthorized(missing, config), false);
	// A slave with no key configured authorizes nobody.
	assert.equal(
		slaveRequestAuthorized(ok, shardConfig({ ROLE: "slave" })),
		false,
	);
});

test("mergeStructured concatenates arrays, sums counters, keeps local scalars", () => {
	const merged = mergeStructured(
		{ accounts: [{ id: "a" }], count: 2, total: 5, status: "ok", message: "local" },
		{ accounts: [{ id: "b" }], count: 3, total: 7, status: "ok", message: "remote", extra: 1 },
	);
	assert.deepEqual(merged.accounts, [{ id: "a" }, { id: "b" }]);
	assert.equal(merged.count, 5);
	assert.equal(merged.total, 12);
	assert.equal(merged.message, "local");
	assert.equal(merged.extra, 1);
});

test("ShardClient performs the MCP handshake and returns the tool result", async () => {
	const seen: Array<{ method?: string; headers: Headers }> = [];
	const fetchFn = async (url: string, init: any) => {
		const payload = JSON.parse(init.body);
		seen.push({ method: payload.method, headers: new Headers(init.headers) });
		if (payload.method === "initialize") {
			return new Response(
				JSON.stringify({ jsonrpc: "2.0", id: 1, result: { protocolVersion: "2025-03-26" } }),
				{ headers: { "Content-Type": "application/json", "Mcp-Session-Id": "sess-1" } },
			);
		}
		if (payload.method === "notifications/initialized") {
			return new Response(null, { status: 202 });
		}
		return new Response(
			JSON.stringify({
				jsonrpc: "2.0",
				id: 2,
				result: {
					content: [{ type: "text", text: "{}" }],
					structuredContent: { accounts: [{ id: "slave-1", email: "s@example.com" }] },
				},
			}),
			{ headers: { "Content-Type": "application/json" } },
		);
	};
	const client = new ShardClient("https://slave.example/mcp", "k3y", fetchFn as typeof fetch);
	const accounts = await client.listAccounts();
	assert.deepEqual(accounts, [{ id: "slave-1", email: "s@example.com" }]);
	assert.deepEqual(
		seen.map((entry) => entry.method),
		["initialize", "notifications/initialized", "tools/call"],
	);
	for (const entry of seen) assert.equal(entry.headers.get("X-Internal-Key"), "k3y");
	assert.equal(seen[2].headers.get("Mcp-Session-Id"), "sess-1");
});

test("ShardClient reads SSE-framed responses", async () => {
	const fetchFn = async (_url: string, init: any) => {
		const payload = JSON.parse(init.body);
		if (payload.method === "initialize") {
			return new Response(
				'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{}}\n\n',
				{ headers: { "Content-Type": "text/event-stream", "Mcp-Session-Id": "s" } },
			);
		}
		if (payload.method === "notifications/initialized") return new Response(null, { status: 202 });
		return new Response(
			'event: message\ndata: {"jsonrpc":"2.0","id":2,"result":{"structuredContent":{"removed":"x"}}}\n\n',
			{ headers: { "Content-Type": "text/event-stream" } },
		);
	};
	const client = new ShardClient("https://slave.example/mcp", "k3y", fetchFn as typeof fetch);
	const result = await client.callTool("email_remove_account", { accountId: "x" });
	assert.deepEqual(result.structuredContent, { removed: "x" });
});

test("pushAccountsToSlave posts records to the slave import endpoint", async () => {
	const { pushAccountsToSlave, handleSlaveImport } = await import("../src/shard.ts");
	let seenUrl = "";
	let seenKey: string | null = null;
	let seenBody = "";
	const fetchFn = async (url: string, init: any) => {
		seenUrl = url;
		seenKey = new Headers(init.headers).get("X-Internal-Key");
		seenBody = init.body;
		return Response.json({ imported: 2 });
	};
	const config = shardConfig({
		SLAVE_MCP_URL: "https://slave.example/mcp",
		SLAVE_INTERNAL_KEY: "shared-key",
	});
	const imported = await pushAccountsToSlave(config, [{ id: "1" }, { id: "2" }], fetchFn as typeof fetch);
	assert.equal(imported, 2);
	assert.equal(seenUrl, "https://slave.example/internal/import-accounts");
	assert.equal(seenKey, "shared-key");
	assert.deepEqual(JSON.parse(seenBody), { accounts: [{ id: "1" }, { id: "2" }] });

	// Import handler validates shape and stores through the given store.
	let stored: unknown[] = [];
	const store = {
		importAccounts: async (accounts: never[]) => {
			stored = accounts;
			return accounts.length;
		},
	};
	const bad = await handleSlaveImport(
		new Request("https://slave.example/internal/import-accounts", {
			method: "POST",
			body: JSON.stringify({ accounts: [{ id: 1 }] }),
		}),
		store,
	);
	assert.equal(bad.status, 400);
	const good = await handleSlaveImport(
		new Request("https://slave.example/internal/import-accounts", {
			method: "POST",
			body: JSON.stringify({
				accounts: [{ id: "a", email: "a@example.com", imap: {}, auth: { type: "password" } }],
			}),
		}),
		store,
	);
	assert.equal(good.status, 200);
	assert.deepEqual(await good.json(), { imported: 1 });
	assert.equal(stored.length, 1);
});

test("slave export returns full records and rejects unknown IDs", async () => {
	const { handleSlaveExport, exportAccountsFromSlave } = await import("../src/shard.ts");
	const store = {
		get: async (id: string) => {
			if (id !== "a") throw new Error("not found");
			return { id: "a", email: "a@example.com" };
		},
	};
	const ok = await handleSlaveExport(
		new Request("https://slave.example/internal/export-accounts", {
			method: "POST",
			body: JSON.stringify({ accountIds: ["a"] }),
		}),
		store,
	);
	assert.equal(ok.status, 200);
	assert.deepEqual(await ok.json(), { accounts: [{ id: "a", email: "a@example.com" }] });
	const missing = await handleSlaveExport(
		new Request("https://slave.example/internal/export-accounts", {
			method: "POST",
			body: JSON.stringify({ accountIds: ["zzz"] }),
		}),
		store,
	);
	assert.equal(missing.status, 404);

	let seenUrl = "";
	const fetchFn = async (url: string, init: any) => {
		seenUrl = url;
		return Response.json({ accounts: [{ id: "a" }] });
	};
	const config = shardConfig({
		SLAVE_MCP_URL: "https://slave.example/mcp",
		SLAVE_INTERNAL_KEY: "k",
	});
	assert.deepEqual(await exportAccountsFromSlave(config, ["a"], fetchFn as typeof fetch), [{ id: "a" }]);
	assert.equal(seenUrl, "https://slave.example/internal/export-accounts");
});

test("a slave account edit round-trips through export and import, preserving credentials", async () => {
	const { pushAccountsToSlave, exportAccountsFromSlave, handleSlaveImport, handleSlaveExport } =
		await import("../src/shard.ts");
	const { AccountStore } = await import("../src/mail/account-store.ts");
	type MailAccount = import("../src/mail/types.ts").MailAccount;

	// The slave's own store, backed by an in-memory KV.
	const key = Buffer.alloc(32, 7).toString("base64");
	class FakeKv {
		value: ArrayBuffer | undefined;
		async get(): Promise<ArrayBuffer | null> {
			return this.value ?? null;
		}
		async put(_key: string, value: ArrayBuffer): Promise<void> {
			this.value = value;
		}
	}
	const store = new AccountStore(new FakeKv() as unknown as KVNamespace, key);
	const slaveStore = {
		importAccounts: (accounts: never[]) => store.importAccounts(accounts as MailAccount[]),
		get: (id: string) => store.get(id),
	};
	const original: MailAccount = {
		id: "slave-acct-1",
		name: "Original Name",
		email: "person@example.com",
		imap: { host: "imap.example.com", port: 993, secure: true },
		smtp: { host: "smtp.example.com", port: 465, secure: true },
		auth: { type: "password", password: "app-password-123" },
	};
	await store.importAccounts([original]);

	// The internal channel between master and slave, routed in-process.
	const seen: Array<{ url: string; key: string | null }> = [];
	const fetchFn = async (url: string, init: any) => {
		seen.push({ url, key: new Headers(init.headers).get("X-Internal-Key") });
		const request = new Request(url, { method: "POST", body: init.body });
		if (url.endsWith("/internal/export-accounts")) return handleSlaveExport(request, slaveStore);
		if (url.endsWith("/internal/import-accounts")) return handleSlaveImport(request, slaveStore);
		throw new Error(`Unexpected URL ${url}`);
	};
	const config = shardConfig({
		SLAVE_MCP_URL: "https://slave.example/mcp",
		SLAVE_INTERNAL_KEY: "shared-key",
	});

	// Mirror of the management page's slave update route: export the real
	// record, apply the form edit on top of it, push the record back.
	const exported = (await exportAccountsFromSlave(
		config,
		["slave-acct-1"],
		fetchFn as typeof fetch,
	)) as MailAccount[];
	assert.equal(exported.length, 1);
	const edited: MailAccount = {
		...exported[0],
		name: "Renamed Account",
		aliases: ["alias@example.com"],
		defaultFrom: "alias@example.com",
	};
	await pushAccountsToSlave(config, [edited], fetchFn as typeof fetch);

	assert.deepEqual(
		seen.map((entry) => entry.url),
		["https://slave.example/internal/export-accounts", "https://slave.example/internal/import-accounts"],
	);
	for (const entry of seen) assert.equal(entry.key, "shared-key");

	const accounts = await store.list();
	assert.equal(accounts.length, 1);
	assert.equal(accounts[0].id, "slave-acct-1");
	assert.equal(accounts[0].name, "Renamed Account");
	assert.equal(accounts[0].defaultFrom, "alias@example.com");
	assert.deepEqual(accounts[0].aliases, ["alias@example.com"]);
	// The credential and connection settings survive the round trip untouched.
	assert.deepEqual(accounts[0].auth, { type: "password", password: "app-password-123" });
	assert.deepEqual(accounts[0].imap, original.imap);
	assert.deepEqual(accounts[0].smtp, original.smtp);

	// Without a linked slave the push refuses before any request is made.
	await assert.rejects(pushAccountsToSlave(shardConfig({}), [edited]), /No slave deployment/);
});

test("shard settings store round-trips encrypted settings and resolve prefers KV over env", async () => {
	const { ShardSettingsStore, resolveShardConfig } = await import("../src/shard.ts");
	const { sealJson } = await import("../src/crypto.ts");
	void sealJson;
	const key = btoa(String.fromCharCode(...new Uint8Array(32).map((_, i) => i + 1)));
	const backing = new Map<string, ArrayBuffer>();
	const kv = {
		get: async (k: string, _t: string) => backing.get(k) ?? null,
		put: async (k: string, v: ArrayBuffer) => void backing.set(k, v),
		delete: async (k: string) => void backing.delete(k),
	};
	const store = new ShardSettingsStore(kv as never, key);
	assert.equal(await store.get(), undefined);
	await store.set({ slaveUrl: "https://slave.example/mcp", slaveKey: "k2" });
	assert.deepEqual(await store.get(), { slaveUrl: "https://slave.example/mcp", slaveKey: "k2" });
	const resolved = await resolveShardConfig(
		{ SLAVE_MCP_URL: "https://env.example/mcp", SLAVE_INTERNAL_KEY: "env-key" },
		store,
	);
	assert.equal(resolved.slaveUrl, "https://slave.example/mcp");
	assert.equal(resolved.slaveKey, "k2");
	await store.clear();
	assert.equal(await store.get(), undefined);
	const fallback = await resolveShardConfig(
		{ SLAVE_MCP_URL: "https://env.example/mcp", SLAVE_INTERNAL_KEY: "env-key" },
		store,
	);
	assert.equal(fallback.slaveUrl, "https://env.example/mcp");
});

test("slave OAuth status reports presence and client IDs only, never secret values", async () => {
	const { slaveOAuthStatusFromEnv, handleSlaveOAuthStatus } = await import("../src/shard.ts");
	const status = slaveOAuthStatusFromEnv({
		GOOGLE_CLIENT_ID: "g-client.apps.googleusercontent.com",
		GOOGLE_CLIENT_SECRET: "g-secret-value",
		OUTLOOK_CLIENT_ID: "o-client-id",
		// OUTLOOK_CLIENT_SECRET deliberately absent (e.g. set under a wrong name).
	});
	assert.deepEqual(status, {
		google: { configured: true, clientId: "g-client.apps.googleusercontent.com" },
		outlook: { configured: false, clientId: "o-client-id" },
	});
	const body = await (await handleSlaveOAuthStatus({
		GOOGLE_CLIENT_ID: "g",
		GOOGLE_CLIENT_SECRET: "g-secret-value",
	})).json();
	assert.equal(JSON.stringify(body).includes("g-secret-value"), false);
});

test("migration gate pauses the move when the slave lacks the provider secret", async () => {
	const { pushAccountsToSlave } = await import("../src/shard.ts");
	const config = shardConfig({
		SLAVE_MCP_URL: "https://slave.example/mcp",
		SLAVE_INTERNAL_KEY: "shared-key",
	});
	const calls: string[] = [];
	const fetchFn = async (url: string) => {
		calls.push(url);
		if (url.endsWith("/internal/oauth-status"))
			return Response.json({
				google: { configured: false, clientId: "g-id" },
				outlook: { configured: true, clientId: "o-id" },
			});
		return Response.json({ imported: 1 });
	};
	const googleAccount = {
		id: "g1",
		email: "person@gmail.com",
		imap: {},
		auth: { type: "oauth2", provider: "google", clientId: "g-id", refreshToken: "r" },
	};
	await assert.rejects(
		pushAccountsToSlave(config, [googleAccount], fetchFn as typeof fetch),
		/paused: the slave is missing GOOGLE_CLIENT_SECRET/,
	);
	// The import endpoint must never be reached when the gate refuses.
	assert.deepEqual(calls, ["https://slave.example/internal/oauth-status"]);

	// Same account, slave now configured with a matching client ID: move proceeds.
	const okFetch = async (url: string) => {
		if (url.endsWith("/internal/oauth-status"))
			return Response.json({
				google: { configured: true, clientId: "g-id" },
				outlook: { configured: false },
			});
		return Response.json({ imported: 1 });
	};
	assert.equal(await pushAccountsToSlave(config, [googleAccount], okFetch as typeof fetch), 1);

	// Client ID mismatch is also a hard stop.
	const mismatchFetch = async (url: string) => {
		if (url.endsWith("/internal/oauth-status"))
			return Response.json({
				google: { configured: true, clientId: "other-id" },
				outlook: { configured: false },
			});
		return Response.json({ imported: 1 });
	};
	await assert.rejects(
		pushAccountsToSlave(config, [googleAccount], mismatchFetch as typeof fetch),
		/client ID for google does not match/,
	);

	// Password accounts need no provider secret and skip the status check.
	let statusCalls = 0;
	const passwordFetch = async (url: string) => {
		if (url.endsWith("/internal/oauth-status")) statusCalls++;
		return Response.json({ imported: 1 });
	};
	const passwordAccount = {
		id: "p1",
		email: "person@yahoo.com",
		imap: {},
		auth: { type: "password", password: "x" },
	};
	assert.equal(await pushAccountsToSlave(config, [passwordAccount], passwordFetch as typeof fetch), 1);
	assert.equal(statusCalls, 0);

	// Edit push-backs opt out of the gate entirely.
	assert.equal(
		await pushAccountsToSlave(config, [googleAccount], passwordFetch as typeof fetch, {
			skipOAuthGate: true,
		}),
		1,
	);
	assert.equal(statusCalls, 0);

	// A slave too old to answer the status endpoint also pauses the move.
	const legacyFetch = async () => new Response("Not found", { status: 404 });
	await assert.rejects(
		pushAccountsToSlave(config, [googleAccount], legacyFetch as typeof fetch),
		/could not be verified/,
	);
});
