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
