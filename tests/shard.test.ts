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
