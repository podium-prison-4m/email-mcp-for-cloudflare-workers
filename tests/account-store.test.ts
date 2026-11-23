import assert from "node:assert/strict";
import test from "node:test";
import { AccountStore } from "../src/mail/account-store.ts";
import { encrypt } from "../src/crypto.ts";
import type { MailAccount } from "../src/mail/types.ts";

const key = Buffer.alloc(32, 7).toString("base64");
const STORAGE_KEY = "mail/accounts/v1";

function account(id: string, email: string): MailAccount {
	return {
		id,
		name: email,
		email,
		imap: { host: "imap.example.com", port: 993, secure: true },
		auth: { type: "password", password: "secret" },
	};
}

class FakeKv {
	value: ArrayBuffer | undefined;
	putAttempts = 0;
	failuresBeforeSuccess: number;
	constructor(failuresBeforeSuccess: number) {
		this.failuresBeforeSuccess = failuresBeforeSuccess;
	}
	async get(): Promise<ArrayBuffer | null> {
		return this.value ?? null;
	}
	async put(_key: string, value: ArrayBuffer): Promise<void> {
		this.putAttempts++;
		if (this.putAttempts <= this.failuresBeforeSuccess) {
			throw new Error("KV PUT failed: 429 Too Many Requests");
		}
		this.value = value;
	}
}

test("update retries a 429 KV write with backoff and succeeds", async () => {
	const kv = new FakeKv(2);
	const store = new AccountStore(kv as unknown as KVNamespace, key);
	const plaintext = new TextEncoder().encode(JSON.stringify([account("a", "a@example.com")]));
	kv.value = await encrypt(plaintext, key);

	await store.update({ ...account("a", "a@example.com"), name: "Renamed" });

	assert.equal(kv.putAttempts, 3);
	const accounts = await store.list();
	assert.equal(accounts[0].name, "Renamed");
});

test("a retry re-reads the bundle so a concurrent writer is not clobbered", async () => {
	const kv = new FakeKv(1);
	const store = new AccountStore(kv as unknown as KVNamespace, key);
	const plaintext = new TextEncoder().encode(JSON.stringify([account("a", "a@example.com")]));
	kv.value = await encrypt(plaintext, key);

	// While the first put is being rejected, another writer saves account b.
	const originalPut = kv.put.bind(kv);
	let injected = false;
	kv.put = async (k: string, v: ArrayBuffer) => {
		try {
			await originalPut(k, v);
		} finally {
			if (!injected) {
				injected = true;
				const bundle = JSON.stringify([account("a", "a@example.com"), account("b", "b@example.com")]);
				kv.value = await encrypt(new TextEncoder().encode(bundle), key);
			}
		}
	};

	await store.update({ ...account("a", "a@example.com"), name: "Renamed" });

	const accounts = await store.list();
	assert.deepEqual(
		accounts.map((entry) => entry.id).sort(),
		["a", "b"],
	);
	assert.equal(accounts.find((entry) => entry.id === "a")?.name, "Renamed");
});

test("non-429 KV errors are not retried", async () => {
	const kv = new FakeKv(0);
	kv.put = async () => {
		kv.putAttempts++;
		throw new Error("KV PUT failed: 500 Internal Error");
	};
	const store = new AccountStore(kv as unknown as KVNamespace, key);
	const plaintext = new TextEncoder().encode(JSON.stringify([account("a", "a@example.com")]));
	kv.value = await encrypt(plaintext, key);

	await assert.rejects(store.update(account("a", "a@example.com")), /500/);
	assert.equal(kv.putAttempts, 1);
});
