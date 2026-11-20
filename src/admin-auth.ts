// Optional administrator username/password sign-in for the web management UI.
//
// Cloudflare Access remains the authentication gate for the MCP endpoint.
// This module provides an alternative credential for the management pages
// only: a single operator-chosen username and password (the ADMIN_USERNAME
// variable, default "admin", and the ADMIN_PASSWORD secret). A successful
// sign-in issues an encrypted session cookie sealed with the same
// CREDENTIAL_ENCRYPTION_KEY that protects stored mailbox credentials, so no
// additional secret material is required. Failed attempts are throttled per
// client IP through the EMAIL_KV namespace.

import { openJson, sealJson } from "./crypto.ts";

export interface AdminAuthEnv {
	ADMIN_USERNAME?: string;
	ADMIN_PASSWORD?: string;
	CREDENTIAL_ENCRYPTION_KEY: string;
	EMAIL_KV: KVNamespace;
}

export const ADMIN_SESSION_COOKIE = "admin_session";
const SESSION_MAX_AGE_SECONDS = 60 * 60 * 24;
const THROTTLE_LIMIT = 5;
const THROTTLE_WINDOW_MS = 15 * 60 * 1000;

interface AdminSession {
	u: string;
	exp: number;
}

interface ThrottleState {
	fails: number;
	resetAt: number;
}

export function adminLoginConfigured(env: AdminAuthEnv): boolean {
	return typeof env.ADMIN_PASSWORD === "string" && env.ADMIN_PASSWORD.length > 0;
}

export function adminUsername(env: AdminAuthEnv): string {
	return env.ADMIN_USERNAME?.trim() || "admin";
}

async function sha256(value: string): Promise<Uint8Array> {
	return new Uint8Array(
		await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
	);
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
	return diff === 0;
}

export async function verifyAdminCredentials(
	env: AdminAuthEnv,
	username: string,
	password: string,
): Promise<boolean> {
	const configuredPassword = env.ADMIN_PASSWORD;
	if (!configuredPassword) return false;
	// Compare SHA-256 digests so the comparison is constant-time and never
	// short-circuits on the username before checking the password.
	const [expectedUser, expectedPassword, givenUser, givenPassword] = await Promise.all([
		sha256(adminUsername(env)),
		sha256(configuredPassword),
		sha256(username),
		sha256(password),
	]);
	return timingSafeEqual(expectedUser, givenUser) && timingSafeEqual(expectedPassword, givenPassword);
}

export async function createAdminSessionCookie(
	env: AdminAuthEnv,
	secure: boolean,
): Promise<string> {
	const session: AdminSession = {
		u: adminUsername(env),
		exp: Date.now() + SESSION_MAX_AGE_SECONDS * 1000,
	};
	const value = await sealJson(session, env.CREDENTIAL_ENCRYPTION_KEY);
	return `${ADMIN_SESSION_COOKIE}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_MAX_AGE_SECONDS}${secure ? "; Secure" : ""}`;
}

export function clearAdminSessionCookie(secure: boolean): string {
	return `${ADMIN_SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure ? "; Secure" : ""}`;
}

function cookieValue(request: Request, name: string): string | undefined {
	for (const part of (request.headers.get("Cookie") || "").split(";")) {
		const separator = part.indexOf("=");
		if (separator < 0 || part.slice(0, separator).trim() !== name) continue;
		return part.slice(separator + 1).trim() || undefined;
	}
	return undefined;
}

export async function adminSessionUser(
	request: Request,
	env: AdminAuthEnv,
): Promise<string | undefined> {
	const raw = cookieValue(request, ADMIN_SESSION_COOKIE);
	if (!raw) return undefined;
	try {
		const session = await openJson<AdminSession>(raw, env.CREDENTIAL_ENCRYPTION_KEY);
		if (typeof session?.u !== "string" || typeof session?.exp !== "number")
			return undefined;
		if (session.exp <= Date.now()) return undefined;
		if (session.u !== adminUsername(env)) return undefined;
		return session.u;
	} catch {
		return undefined;
	}
}

function throttleKey(ip: string): string {
	return `admin-login-throttle:${ip}`;
}

export async function loginThrottled(env: AdminAuthEnv, ip: string): Promise<boolean> {
	try {
		const state = await env.EMAIL_KV.get<ThrottleState>(throttleKey(ip), "json");
		return !!state && state.resetAt > Date.now() && state.fails >= THROTTLE_LIMIT;
	} catch {
		return false;
	}
}

export async function recordLoginFailure(env: AdminAuthEnv, ip: string): Promise<void> {
	const now = Date.now();
	let state: ThrottleState | null = null;
	try {
		state = await env.EMAIL_KV.get<ThrottleState>(throttleKey(ip), "json");
	} catch {
		state = null;
	}
	if (!state || state.resetAt <= now) state = { fails: 0, resetAt: now + THROTTLE_WINDOW_MS };
	state.fails += 1;
	await env.EMAIL_KV.put(throttleKey(ip), JSON.stringify(state), {
		expirationTtl: Math.max(60, Math.ceil((state.resetAt - now) / 1000) + 60),
	});
}

export async function clearLoginFailures(env: AdminAuthEnv, ip: string): Promise<void> {
	await env.EMAIL_KV.delete(throttleKey(ip));
}
