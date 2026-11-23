import type { MailAccount } from "./types";
import { decrypt, encrypt } from "../crypto.ts";
import { senderSettings } from "./sender.ts";

const STORAGE_KEY = "mail/accounts/v1";

// All accounts live in a single KV value, and Cloudflare KV allows only one
// write per second to the same key. Concurrent token refreshes (one per
// OAuth account) can therefore collide and get a 429 from kv.put. Retrying
// with backoff — and re-reading the bundle before each retry so a concurrent
// writer's update is not clobbered — makes those writes reliable.
const PUT_RETRY_DELAYS_MS = [1200, 2500, 5000];

function isRateLimitError(error: unknown): boolean {
	const message = error instanceof Error ? error.message : String(error);
	return /429|too many requests|rate.?limit/i.test(message);
}

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

export class AccountStore {
	private kv: KVNamespace;
	private encryptionKey: string;

	constructor(kv: KVNamespace, encryptionKey: string) {
		this.kv = kv;
		this.encryptionKey = encryptionKey;
	}

	async list(): Promise<MailAccount[]> {
		const encoded = await this.kv.get(STORAGE_KEY, "arrayBuffer");
		if (!encoded) return [];
		const plaintext = await decrypt(encoded, this.encryptionKey);
		return JSON.parse(new TextDecoder().decode(plaintext)) as MailAccount[];
	}

	async get(id?: string): Promise<MailAccount> {
		const accounts = await this.list();
		if (id) {
			const account = accounts.find((candidate) => candidate.id === id);
			if (!account) throw new Error(`Account ${id} not found`);
			return account;
		}
		if (accounts.length === 1) return accounts[0];
		if (accounts.length === 0) throw new Error("No email accounts configured");
		throw new Error("Multiple accounts configured; accountId is required");
	}

	async add(account: Omit<MailAccount, "id">): Promise<MailAccount> {
		const created = { ...account, ...senderSettings(account), id: crypto.randomUUID() };
		await this.mutate((accounts) => [...accounts, created]);
		return created;
	}

	async update(account: MailAccount): Promise<void> {
		await this.mutate((accounts) => {
			const index = accounts.findIndex((candidate) => candidate.id === account.id);
			if (index < 0) throw new Error(`Account ${account.id} not found`);
			const next = [...accounts];
			next[index] = { ...account, ...senderSettings(account) };
			return next;
		});
	}

	async updateSender(
		id: string | undefined,
		input: { aliases?: string[]; defaultFrom?: string },
	) {
		const account = await this.get(id);
		const settings = senderSettings({ ...account, ...input });
		await this.update({ ...account, ...settings });
		return { accountId: account.id, email: account.email, ...settings };
	}

	async remove(id: string): Promise<void> {
		await this.mutate((accounts) => {
			const remaining = accounts.filter((account) => account.id !== id);
			if (remaining.length === accounts.length) throw new Error(`Account ${id} not found`);
			return remaining;
		});
	}

	// Read-modify-write with retry: every attempt re-reads the current bundle
	// and re-applies the mutation, so retries never overwrite an update that
	// another writer saved in the meantime.
	private async mutate(mutation: (accounts: MailAccount[]) => MailAccount[]): Promise<void> {
		for (let attempt = 0; ; attempt++) {
			const accounts = mutation(await this.list());
			try {
				await this.save(accounts);
				return;
			} catch (error) {
				if (!isRateLimitError(error) || attempt >= PUT_RETRY_DELAYS_MS.length) throw error;
				await sleep(PUT_RETRY_DELAYS_MS[attempt]);
			}
		}
	}

	private async save(accounts: MailAccount[]): Promise<void> {
		const plaintext = new TextEncoder().encode(JSON.stringify(accounts));
		await this.kv.put(STORAGE_KEY, await encrypt(plaintext, this.encryptionKey));
	}
}
