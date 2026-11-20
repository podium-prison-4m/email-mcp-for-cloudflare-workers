import assert from "node:assert/strict";
import test from "node:test";
import {
	ADMIN_SESSION_COOKIE,
	adminLoginConfigured,
	adminSessionUser,
	clearLoginFailures,
	createAdminSessionCookie,
	loginThrottled,
	recordLoginFailure,
	verifyAdminCredentials,
	type AdminAuthEnv,
} from "../src/admin-auth.ts";
import { sealJson } from "../src/crypto.ts";

const key = Buffer.alloc(32, 7).toString("base64");

class KvStub {
	readonly values = new Map<string, string>();

	async get(key: string, type?: string) {
		const raw = this.values.get(key);
		if (raw === undefined) return null;
		return type === "json" ? JSON.parse(raw) : raw;
	}

	async put(key: string, value: string) {
		this.values.set(key, value);
	}

	async delete(key: string) {
		this.values.delete(key);
	}
}

function makeEnv(overrides: Partial<AdminAuthEnv> = {}): AdminAuthEnv {
	return {
		ADMIN_PASSWORD: "correct horse battery staple",
		CREDENTIAL_ENCRYPTION_KEY: key,
		EMAIL_KV: new KvStub() as unknown as KVNamespace,
		...overrides,
	};
}

function requestWithCookie(cookie: string): Request {
	return new Request("https://example.com/", { headers: { Cookie: cookie } });
}

function sessionCookieValue(setCookie: string): string {
	const prefix = `${ADMIN_SESSION_COOKIE}=`;
	assert.ok(setCookie.startsWith(prefix));
	return setCookie.slice(prefix.length, setCookie.indexOf(";"));
}

test("credentials verify against the default admin username", async () => {
	const env = makeEnv();
	assert.equal(adminLoginConfigured(env), true);
	assert.equal(await verifyAdminCredentials(env, "admin", "correct horse battery staple"), true);
	assert.equal(await verifyAdminCredentials(env, "admin", "wrong"), false);
	assert.equal(await verifyAdminCredentials(env, "root", "correct horse battery staple"), false);
	assert.equal(await verifyAdminCredentials(env, "", ""), false);
});

test("a custom ADMIN_USERNAME replaces the default", async () => {
	const env = makeEnv({ ADMIN_USERNAME: "neo" });
	assert.equal(await verifyAdminCredentials(env, "neo", "correct horse battery staple"), true);
	assert.equal(await verifyAdminCredentials(env, "admin", "correct horse battery staple"), false);
});

test("sign-in is disabled when ADMIN_PASSWORD is not set", async () => {
	const env = makeEnv({ ADMIN_PASSWORD: undefined });
	assert.equal(adminLoginConfigured(env), false);
	assert.equal(await verifyAdminCredentials(env, "admin", "correct horse battery staple"), false);
});

test("session cookies round-trip and reject tampering and expiry", async () => {
	const env = makeEnv();
	const setCookie = await createAdminSessionCookie(env, true);
	assert.match(setCookie, /HttpOnly; SameSite=Lax; Max-Age=86400; Secure/);
	const value = sessionCookieValue(setCookie);
	assert.equal(await adminSessionUser(requestWithCookie(`${ADMIN_SESSION_COOKIE}=${value}`), env), "admin");

	const tampered = `${value.slice(0, -2)}${value.endsWith("A") ? "B" : "A"}${value.slice(-1)}`;
	assert.equal(await adminSessionUser(requestWithCookie(`${ADMIN_SESSION_COOKIE}=${tampered}`), env), undefined);

	const expired = await sealJson({ u: "admin", exp: Date.now() - 1000 }, key);
	assert.equal(await adminSessionUser(requestWithCookie(`${ADMIN_SESSION_COOKIE}=${expired}`), env), undefined);

	const otherUser = await sealJson({ u: "root", exp: Date.now() + 60000 }, key);
	assert.equal(await adminSessionUser(requestWithCookie(`${ADMIN_SESSION_COOKIE}=${otherUser}`), env), undefined);

	assert.equal(await adminSessionUser(new Request("https://example.com/"), env), undefined);
});

test("login throttling blocks after five failures until cleared", async () => {
	const env = makeEnv();
	const ip = "203.0.113.9";
	assert.equal(await loginThrottled(env, ip), false);
	for (let i = 0; i < 4; i++) await recordLoginFailure(env, ip);
	assert.equal(await loginThrottled(env, ip), false);
	await recordLoginFailure(env, ip);
	assert.equal(await loginThrottled(env, ip), true);
	assert.equal(await loginThrottled(env, "198.51.100.4"), false);
	await clearLoginFailures(env, ip);
	assert.equal(await loginThrottled(env, ip), false);
});
