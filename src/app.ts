import { Hono, type Context } from "hono";
import { createRemoteJWKSet, decodeJwt, jwtVerify } from "jose";
import {
	adminLoginConfigured,
	adminSessionUser,
	clearAdminSessionCookie,
	clearLoginFailures,
	createAdminSessionCookie,
	loginThrottled,
	recordLoginFailure,
	verifyAdminCredentials,
} from "./admin-auth";
import { openJson, sealJson } from "./crypto";
import { LOGO_SVG } from "./logo";
import { AccountStore } from "./mail/account-store";
import { MailService } from "./mail/mail-service";
import { senderSettings } from "./mail/sender";
import type { AccountAuth, MailAccount, MailEnv } from "./mail/types";
import {
	assertValidOutlookOAuthCallback,
	createOutlookOAuthState,
	type OutlookOAuthState,
} from "./outlook-oauth";
import {
	assertValidGoogleOAuthCallback,
	createGoogleOAuthState,
	type GoogleOAuthState,
} from "./google-oauth";

const app = new Hono<{ Bindings: MailEnv }>();
const OUTLOOK_SCOPES =
	"openid profile email offline_access https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send";
const microsoftJwks = createRemoteJWKSet(
	new URL("https://login.microsoftonline.com/common/discovery/v2.0/keys"),
);
const GOOGLE_SCOPES = "openid email profile https://mail.google.com/";
const googleJwks = createRemoteJWKSet(
	new URL("https://www.googleapis.com/oauth2/v3/certs"),
);

type MailContext = Context<{ Bindings: MailEnv }>;

interface PendingAccountChange {
	mode: "add" | "update";
	accountId?: string;
	account: Omit<MailAccount, "id">;
	createdAt: number;
}

app.get("/", async (c) => {
	try {
		const accounts = await accountStore(c.env).list();
		const editId = c.req.query("edit");
		const editAccount = editId ? accounts.find((account) => account.id === editId) : undefined;
		const hasAdminSession = (await adminSessionUser(c.req.raw, c.env)) !== undefined;
		const connectionFlash = cookieValue(c.req.raw, "connection_test");
		if (connectionFlash)
			c.header("Set-Cookie", clearConnectionTestCookie(c.req.url.startsWith("https://")));
		if (editId && !editAccount) throw new Error("Account to edit was not found");
		return c.html(
			managementPage(
				accounts,
				c.req.query("status") ||
					(connectionFlash === "connection_ok" ||
					connectionFlash === "connection_imap_only"
						? connectionFlash
						: undefined),
				undefined,
				outlookConfigured(c.env), googleConfigured(c.env),
				editAccount,
				undefined,
				hasAdminSession,
			),
		);
	} catch (error) {
		return c.html(
			managementPage([], undefined, errorMessage(error), outlookConfigured(c.env), googleConfigured(c.env)),
			500,
		);
	}
});

app.get("/logo.svg", (c) =>
	c.body(LOGO_SVG, 200, {
		"Content-Type": "image/svg+xml; charset=utf-8",
		"Cache-Control": "public, max-age=86400",
	}),
);
app.get("/home", (c) => c.html(legalPage("Email MCP Server", HOME_PAGE_BODY, "")));
app.get("/privacy", (c) => c.html(legalPage("Privacy Policy", PRIVACY_POLICY_BODY)));
app.get("/service", (c) => c.html(legalPage("Terms of Service", TERMS_OF_SERVICE_BODY)));

app.get("/login", async (c) => {
	if (await adminSessionUser(c.req.raw, c.env)) return c.redirect("/");
	return c.html(loginPage(c.env));
});

app.post("/login", async (c) => {
	if (!adminLoginConfigured(c.env))
		return c.html(
			loginPage(
				c.env,
				"Administrator sign-in is not configured yet. Set the ADMIN_PASSWORD secret for this Worker (and optionally the ADMIN_USERNAME variable), then reload this page.",
			),
			503,
		);
	const ip = c.req.header("CF-Connecting-IP") || "unknown";
	if (await loginThrottled(c.env, ip))
		return c.html(
			loginPage(c.env, "Too many failed sign-in attempts. Try again in 15 minutes."),
			429,
		);
	const form = await c.req.parseBody();
	const username = typeof form.username === "string" ? form.username : "";
	const password = typeof form.password === "string" ? form.password : "";
	if (!(await verifyAdminCredentials(c.env, username, password))) {
		await recordLoginFailure(c.env, ip);
		return c.html(loginPage(c.env, "Invalid username or password."), 401);
	}
	await clearLoginFailures(c.env, ip);
	c.header(
		"Set-Cookie",
		await createAdminSessionCookie(c.env, c.req.url.startsWith("https://")),
	);
	return c.redirect("/");
});

app.post("/logout", (c) => {
	c.header(
		"Set-Cookie",
		clearAdminSessionCookie(c.req.url.startsWith("https://")),
	);
	return c.redirect("/login");
});

function loginPage(env: MailEnv, notice?: string): string {
	const configured = adminLoginConfigured(env);
	const body = `
					<style>
						.login-form { display: grid; gap: 1rem; margin-top: 1.25rem; }
						.login-form label { display: grid; gap: .4rem; font-weight: 600; color: var(--text); }
						.login-form input { width: 100%; padding: .7rem .75rem; font: inherit; color: var(--text); background: var(--surface); border: 1px solid var(--border); border-radius: .45rem; }
						.login-form input:focus { outline: 3px solid rgba(36,95,194,.35); border-color: var(--accent); }
						.login-form button { padding: .7rem 1rem; font: inherit; font-weight: 700; color: #fff; background: var(--accent); border: 0; border-radius: .45rem; cursor: pointer; }
						.login-error { margin-top: 1rem; padding: .8rem 1rem; border-radius: .6rem; color: #8c1d18; background: #fdecea; border: 1px solid #f5c6c2; }
						@media (prefers-color-scheme: dark) { .login-error { color: #ff9c94; background: #3d1f1c; border-color: #6e352f; } }
					</style>
					${notice ? `<div class="login-error" role="alert">${notice}</div>` : ""}
					${
						configured
							? `<form class="login-form" method="post" action="/login">
						<label>Username<input name="username" autocomplete="username" required></label>
						<label>Password<input name="password" type="password" autocomplete="current-password" required></label>
						<button type="submit">Sign in</button>
					</form>`
							: `<p>Administrator sign-in is not configured for this deployment yet.</p>`
					}`;
	return legalPage("Sign in", body, "");
}

function legalPage(title: string, body: string, meta = "Effective date: November 20, 2026"): string {
	return `<!doctype html>
	<html lang="en">
		<head>
			<meta charset="utf-8">
			<meta name="viewport" content="width=device-width, initial-scale=1">
			<meta name="referrer" content="no-referrer">
			<title>${title} — Email MCP Server</title>
			<link rel="icon" type="image/svg+xml" href="/logo.svg">
			<style>
				:root { color-scheme: light dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; color: #172033; background: #eef1f7; --surface: #fff; --border: #dfe3eb; --text: #172033; --muted: #5d6678; --accent: #245fc2; }
				@media (prefers-color-scheme: dark) { :root { color: #e7ecf5; background: #0b1120; --surface: #141c2e; --border: #273350; --text: #e7ecf5; --muted: #9aa7bf; --accent: #6ea8ff; } }
				* { box-sizing: border-box; }
				body { margin: 0; }
				main { width: min(46rem, calc(100% - 2rem)); margin: 3rem auto; }
				.brand { display: flex; gap: .85rem; align-items: center; margin-bottom: 1.5rem; }
				.brand-mark { flex: 0 0 auto; width: 3rem; height: 3rem; border-radius: .85rem; display: block; }
				.brand p { margin: 0; }
				.card { background: var(--surface); border: 1px solid var(--border); border-radius: .9rem; padding: 2rem; box-shadow: 0 8px 28px rgba(23,32,51,.06); }
				h1 { margin: 0 0 .25rem; font-size: 1.9rem; letter-spacing: -.02em; }
				h2 { margin: 1.75rem 0 .5rem; font-size: 1.1rem; }
				h2:first-of-type { margin-top: 1.25rem; }
				p, li { color: var(--muted); line-height: 1.65; }
				p { margin: .5rem 0; }
				ul { margin: .5rem 0; padding-left: 1.25rem; }
				a { color: var(--accent); }
				.meta { color: var(--muted); font-size: .9rem; }
				footer { margin-top: 1.5rem; color: var(--muted); font-size: .85rem; display: flex; gap: 1rem; flex-wrap: wrap; }
			</style>
		</head>
		<body>
			<main>
				<div class="brand"><img class="brand-mark" src="/logo.svg" alt="" aria-hidden="true"><div><strong>Email MCP Server</strong><p class="meta">Self-hosted email management for your own mailboxes</p></div></div>
				<section class="card">
					<h1>${title}</h1>
					${meta ? `<p class="meta">${meta}</p>` : ""}
					${body}
				</section>
				<footer><a href="/privacy">Privacy Policy</a><a href="/service">Terms of Service</a><a href="/">Email account management</a></footer>
			</main>
		</body>
	</html>`;
}


const HOME_PAGE_BODY = `
					<p>Email MCP Server is a self-hosted application that connects your own email accounts to a web management interface and an MCP (Model Context Protocol) server, so you — and AI assistants acting on your instructions — can work with your email from one place.</p>
					<h2>What it does</h2>
					<ul>
						<li>Connect Gmail, Outlook, iCloud, Yahoo, AOL, QQ Mail, NetEase Mail, Tencent Exmail, Fastmail, Zoho, and custom IMAP/SMTP mailboxes you own.</li>
						<li>Search, read, organize, draft, and send email through your own mail provider.</li>
						<li>Sign in to Gmail and Outlook with OAuth — no password is stored for OAuth accounts, and access tokens are encrypted at rest.</li>
						<li>Expose your mailboxes to AI assistants through a standard MCP interface, protected by Cloudflare Access so only authorized identities can use it.</li>
					</ul>
					<h2>How it uses Google data</h2>
					<p>If you connect a Gmail account, the Service accesses your Gmail messages only to carry out actions you direct: displaying, searching, drafting, and sending your email. Google user data is never sold, never used for advertising, and never used to train AI models. The full details are in the <a href="/privacy">Privacy Policy</a>, which follows the Google API Services User Data Policy, including the Limited Use requirements.</p>
					<h2>Access</h2>
					<p>The Service is operated for its owner's own mailboxes. The MCP endpoint requires sign-in through Cloudflare Access, and the management interface requires Cloudflare Access or the operator's administrator password. Neither is open to the public. Read the <a href="/service">Terms of Service</a> for the conditions of use.</p>`;

const PRIVACY_POLICY_BODY = `
					<h2>1. Overview</h2>
					<p>Email MCP Server (the "Service") is a self-hosted application that lets its operator connect their own email accounts and manage them through a web interface and an MCP (Model Context Protocol) interface used by AI assistants acting on the operator's instructions. The Service runs on the operator's own Cloudflare account. In this policy, "we" and "the operator" mean the individual operating this instance of the Service. Contact: <a href="mailto:bowls.heart4v@icloud.com">bowls.heart4v@icloud.com</a>.</p>
					<h2>2. Information the Service processes</h2>
					<p><strong>Mailbox credentials.</strong> When you connect a mailbox, the Service stores the credentials needed to access it: an app-specific password, or OAuth access and refresh tokens issued by your mail provider (Google or Microsoft). Credentials are encrypted at rest with AES-256-GCM and stored in the operator's Cloudflare KV namespace. The encryption key is held separately as a Cloudflare Worker secret and is never written into the credential store.</p>
					<p><strong>Email content.</strong> When you search, read, draft, move, or send email through the Service, message content is retrieved from your mail provider over IMAP or SMTP and processed in memory to carry out your request. The Service does not build or keep a separate archive of your mailbox. Drafts you create are stored in your mailbox on your provider's servers, like drafts created in any other mail client.</p>
					<p><strong>Technical data.</strong> The Service is hosted on Cloudflare, which processes request metadata such as IP addresses and timestamps for security and reliability. The Service uses only strictly necessary cookies: a Cloudflare Access session cookie or an encrypted administrator session cookie that keeps the operator signed in, and short-lived encrypted cookies used to complete OAuth sign-in flows.</p>
					<h2>3. Google user data</h2>
					<p>The Service's use and transfer of information received from Google APIs adheres to the <a href="https://developers.google.com/terms/api-services-user-data-policy">Google API Services User Data Policy</a>, including the Limited Use requirements. Specifically:</p>
					<ul>
						<li>Gmail data is used only to provide user-facing features of the Service: displaying, searching, drafting, and sending your email at your direction.</li>
						<li>We do not sell Google user data, and we do not use it for advertising.</li>
						<li>We do not use Google user data to train generalized artificial intelligence or machine learning models.</li>
						<li>We do not transfer Google user data to third parties except as necessary to provide the Service (your mail provider and Cloudflare as hosting provider), for security purposes, or to comply with applicable law.</li>
						<li>Humans do not read your Gmail data, except the operator where necessary for security or maintenance, or with your consent.</li>
					</ul>
					<h2>4. How information is used</h2>
					<p>Information processed by the Service is used solely to operate the Service at the direction of the authenticated user: connecting to mailboxes, carrying out email actions the user requests, and keeping the Service secure and reliable. It is not used for advertising, profiling, or any other purpose.</p>
					<h2>5. Sharing</h2>
					<p>We do not sell personal information. Data is processed only by the infrastructure providers required to run the Service: Cloudflare (hosting and encrypted credential storage) and the mail providers you choose to connect (such as Google, Microsoft, Apple, or your own IMAP/SMTP provider), under their own privacy policies.</p>
					<h2>6. Retention and deletion</h2>
					<p>Stored credentials remain in the encrypted store until you remove the account from the Service's management page, which deletes them immediately, or until you revoke the Service's access at your provider (for example, from your Google account's third-party access page or your Microsoft account's app consent page), which invalidates the stored tokens. Email itself remains on your mail provider's servers under your provider's retention policies.</p>
					<h2>7. Security</h2>
					<p>Connections to the Service and to mail providers use TLS encryption. Stored credentials are encrypted at rest as described above. The MCP endpoint is restricted by Cloudflare Access to identities the operator has authorized, and the management interface requires Cloudflare Access or the operator's administrator sign-in.</p>
					<h2>8. Your choices</h2>
					<p>Connect only mailboxes you own or are authorized to manage. You may remove a connected account or revoke provider access at any time, which stops all further access to that mailbox through the Service.</p>
					<h2>9. Children</h2>
					<p>The Service is not directed to children under the age of 13, or the minimum age required in your jurisdiction, and is intended for the operator's own accounts.</p>
					<h2>10. Changes to this policy</h2>
					<p>If this policy changes, the updated version will be posted on this page with a new effective date.</p>
					<h2>11. Contact</h2>
					<p>Questions about this policy can be sent to <a href="mailto:bowls.heart4v@icloud.com">bowls.heart4v@icloud.com</a>.</p>`;

const TERMS_OF_SERVICE_BODY = `
					<h2>1. Acceptance of these terms</h2>
					<p>By accessing or using Email MCP Server (the "Service"), you agree to these Terms of Service. If you do not agree, do not use the Service.</p>
					<h2>2. The Service</h2>
					<p>The Service is a self-hosted tool that lets an authorized operator connect their own email accounts and read, search, draft, and send email through a web interface and an MCP (Model Context Protocol) interface used by AI assistants acting on the operator's instructions. You are responsible for the email you send and the actions you direct the Service to take.</p>
					<h2>3. Your accounts and responsibilities</h2>
					<ul>
						<li>Connect only mailboxes that you own or are authorized to manage.</li>
						<li>You are responsible for activity carried out through your connected accounts and for keeping your own provider credentials and devices secure.</li>
						<li>Your use of connected mailboxes remains subject to your mail providers' own terms and policies.</li>
					</ul>
					<h2>4. Acceptable use</h2>
					<p>You agree not to use the Service to break the law, send spam or abusive bulk mail, infringe the rights of others, attempt to bypass the Service's authentication or access controls, or violate the acceptable-use policies of Cloudflare or of any connected mail provider (including Google, Microsoft, and Apple).</p>
					<h2>5. Third-party services</h2>
					<p>The Service runs on Cloudflare and connects to third-party mail providers. Those services are governed by their own terms and privacy policies. The Service is not affiliated with or endorsed by Cloudflare, Google, Microsoft, or Apple.</p>
					<h2>6. Availability and changes</h2>
					<p>The Service is provided on an "as is" and "as available" basis, without warranties of any kind, whether express or implied, including fitness for a particular purpose and uninterrupted availability. The operator may modify, suspend, or discontinue the Service at any time.</p>
					<h2>7. Limitation of liability</h2>
					<p>To the maximum extent permitted by applicable law, the operator is not liable for any indirect, incidental, special, or consequential damages, or for any loss of data, arising from or related to your use of the Service.</p>
					<h2>8. Termination</h2>
					<p>You may stop using the Service at any time and remove your connected accounts from the management page. The operator may suspend or terminate access to protect the Service or to comply with law or provider requirements.</p>
					<h2>9. Governing law</h2>
					<p>These terms are governed by the laws of Singapore, without regard to its conflict-of-law rules.</p>
					<h2>10. Changes to these terms</h2>
					<p>If these terms change, the updated version will be posted on this page with a new effective date. Continued use of the Service after a change takes effect constitutes acceptance of the updated terms.</p>
					<h2>11. Contact</h2>
					<p>Questions about these terms can be sent to <a href="mailto:bowls.heart4v@icloud.com">bowls.heart4v@icloud.com</a>.</p>`;

app.post("/accounts", async (c) => {
	if (!isTrustedFormSubmission(c.req.raw)) return c.text("Forbidden", 403);

	let account: Omit<MailAccount, "id">;
	try {
		const form = await c.req.formData();
		account = accountInput(form);
	} catch (error) {
		const accounts = await accountStore(c.env)
			.list()
			.catch(() => []);
		return c.html(
			managementPage(accounts, undefined, errorMessage(error), outlookConfigured(c.env), googleConfigured(c.env)),
			400,
		);
	}

	let testResult: { smtpConfigured: boolean };
	try {
		testResult = await testNewAccount(c.env, account);
	} catch (error) {
		return accountTestFailureResponse(c, error, {
			mode: "add",
			account,
			createdAt: Date.now(),
		});
	}

	try {
		await accountStore(c.env).add(account);
		return c.redirect(
			testResult.smtpConfigured ? "/?status=added_tested" : "/?status=added_tested_imap_only",
			303,
		);
	} catch (error) {
		const accounts = await accountStore(c.env)
			.list()
			.catch(() => []);
		return c.html(
			managementPage(accounts, undefined, errorMessage(error), outlookConfigured(c.env), googleConfigured(c.env)),
			500,
		);
	}
});

app.post("/accounts/pending/retry", async (c) => {
	if (!isTrustedFormSubmission(c.req.raw)) return c.text("Forbidden", 403);

	let pending: PendingAccountChange;
	try {
		pending = await pendingAccountChange(c.env, await c.req.formData());
	} catch (error) {
		return pendingAccountError(c, error);
	}

	let testResult: { smtpConfigured: boolean };
	try {
		testResult = await testNewAccount(c.env, pending.account);
	} catch (error) {
		return accountTestFailureResponse(c, error, pending);
	}

	try {
		await persistAccountChange(c.env, pending);
		const status = testResult.smtpConfigured
			? pending.mode === "add"
				? "added_tested"
				: "updated_tested"
			: pending.mode === "add"
				? "added_tested_imap_only"
				: "updated_tested_imap_only";
		return c.redirect(`/?status=${status}`, 303);
	} catch (error) {
		return pendingAccountError(c, error);
	}
});

app.post("/accounts/pending/edit-test", async (c) => {
	if (!isTrustedFormSubmission(c.req.raw)) return c.text("Forbidden", 403);

	let pending: PendingAccountChange;
	try {
		const form = await c.req.formData();
		pending = await pendingAccountChange(c.env, form);
		pending.account = accountInput(form, pending.account.auth);
	} catch (error) {
		return pendingAccountError(c, error);
	}

	let testResult: { smtpConfigured: boolean };
	try {
		testResult = await testNewAccount(c.env, pending.account);
	} catch (error) {
		return accountTestFailureResponse(c, error, pending);
	}

	try {
		await persistAccountChange(c.env, pending);
		const status = testResult.smtpConfigured
			? pending.mode === "add"
				? "added_tested"
				: "updated_tested"
			: pending.mode === "add"
				? "added_tested_imap_only"
				: "updated_tested_imap_only";
		return c.redirect(`/?status=${status}`, 303);
	} catch (error) {
		return pendingAccountError(c, error);
	}
});

app.post("/accounts/pending/save", async (c) => {
	if (!isTrustedFormSubmission(c.req.raw)) return c.text("Forbidden", 403);

	try {
		const pending = await pendingAccountChange(c.env, await c.req.formData());
		await persistAccountChange(c.env, pending);
		return c.redirect(
			pending.mode === "add" ? "/?status=added_untested" : "/?status=updated_untested",
			303,
		);
	} catch (error) {
		return pendingAccountError(c, error);
	}
});

app.post("/accounts/pending/cancel", async (c) => {
	if (!isTrustedFormSubmission(c.req.raw)) return c.text("Forbidden", 403);
	return c.redirect("/", 303);
});

app.post("/accounts/:id/update", async (c) => {
	if (!isTrustedFormSubmission(c.req.raw)) return c.text("Forbidden", 403);

	const store = accountStore(c.env);
	let account: MailAccount;
	try {
		const form = await c.req.formData();
		const existing = await store.get(c.req.param("id"));
		account = { id: existing.id, ...accountInput(form, existing.auth) };
		if (
			account.email === existing.email &&
			JSON.stringify(account.imap) === JSON.stringify(existing.imap) &&
			JSON.stringify(account.smtp) === JSON.stringify(existing.smtp)
		) {
			await store.update(account);
			return c.redirect("/?status=updated", 303);
		}
	} catch (error) {
		const accounts = await store.list().catch(() => []);
		const editAccount = accounts.find((account) => account.id === c.req.param("id"));
		return c.html(
			managementPage(
				accounts,
				undefined,
				errorMessage(error),
				outlookConfigured(c.env), googleConfigured(c.env),
				editAccount,
			),
			400,
		);
	}

	let testResult: { smtpConfigured: boolean };
	try {
		testResult = await testNewAccount(c.env, account);
	} catch (error) {
		return accountTestFailureResponse(c, error, {
			mode: "update",
			accountId: account.id,
			account,
			createdAt: Date.now(),
		});
	}

	try {
		await store.update(account);
		return c.redirect(
			testResult.smtpConfigured
				? "/?status=updated_tested"
				: "/?status=updated_tested_imap_only",
			303,
		);
	} catch (error) {
		return pendingAccountError(c, error);
	}
});

app.post("/accounts/:id/test", async (c) => {
	if (!isTrustedFormSubmission(c.req.raw)) return c.text("Forbidden", 403);

	try {
		const mail = new MailService(
			accountStore(c.env),
			{
				clientId: c.env.OUTLOOK_CLIENT_ID,
				clientSecret: c.env.OUTLOOK_CLIENT_SECRET,
			},
			{
				clientId: c.env.GOOGLE_CLIENT_ID,
				clientSecret: c.env.GOOGLE_CLIENT_SECRET,
			},
		);
		const result = await mail.testConnection(c.req.param("id"));
		c.header(
			"Set-Cookie",
			connectionTestCookie(c.req.url.startsWith("https://"), result.smtpConfigured),
		);
		return c.redirect("/", 303);
	} catch (error) {
		const accounts = await accountStore(c.env)
			.list()
			.catch(() => []);
		return c.html(
			managementPage(
				accounts,
				undefined,
				`Connection test failed: ${errorMessage(error)}`,
				outlookConfigured(c.env), googleConfigured(c.env),
			),
			502,
		);
	}
});

app.post("/accounts/:id/remove", async (c) => {
	if (!isTrustedFormSubmission(c.req.raw)) return c.text("Forbidden", 403);

	try {
		await accountStore(c.env).remove(c.req.param("id"));
		return c.redirect("/?status=removed", 303);
	} catch (error) {
		const accounts = await accountStore(c.env)
			.list()
			.catch(() => []);
		return c.html(
			managementPage(accounts, undefined, errorMessage(error), outlookConfigured(c.env), googleConfigured(c.env)),
			400,
		);
	}
});

app.post("/oauth/outlook/start", async (c) => {
	if (!isTrustedFormSubmission(c.req.raw)) return c.text("Forbidden", 403);

	try {
		const config = outlookConfig(c.env);
		const form = await c.req.formData();
		const { oauthState, codeChallenge } = await createOutlookOAuthState(
			validName(required(form, "name")),
		);
		const redirectUri = outlookRedirectUri(c.req.raw);
		const authorize = new URL(
			`https://login.microsoftonline.com/${config.tenant}/oauth2/v2.0/authorize`,
		);
		authorize.search = new URLSearchParams({
			client_id: config.clientId,
			response_type: "code",
			redirect_uri: redirectUri,
			response_mode: "query",
			scope: OUTLOOK_SCOPES,
			state: oauthState.state,
			nonce: oauthState.nonce,
			code_challenge: codeChallenge,
			code_challenge_method: "S256",
			prompt: "select_account",
		}).toString();
		c.header(
			"Set-Cookie",
			oauthCookie(
				await sealJson(oauthState, c.env.CREDENTIAL_ENCRYPTION_KEY),
				c.req.url.startsWith("https://"),
			),
		);
		return c.redirect(authorize.toString(), 303);
	} catch (error) {
		const accounts = await accountStore(c.env)
			.list()
			.catch(() => []);
		return c.html(
			managementPage(accounts, undefined, errorMessage(error), outlookConfigured(c.env), googleConfigured(c.env)),
			400,
		);
	}
});

app.get("/oauth/outlook/callback", async (c) => {
	try {
		const config = outlookConfig(c.env);
		const oauthError = c.req.query("error");
		if (oauthError) throw new Error(`Microsoft authorization failed: ${oauthError}`);
		const code = c.req.query("code");
		const returnedState = c.req.query("state");
		const sealedState = cookieValue(c.req.raw, "outlook_oauth");
		if (!code || !returnedState || !sealedState)
			throw new Error("Outlook authorization expired");
		const oauthState = await openJson<OutlookOAuthState>(
			sealedState,
			c.env.CREDENTIAL_ENCRYPTION_KEY,
		);
		assertValidOutlookOAuthCallback(oauthState, returnedState);

		const body = new URLSearchParams({
			client_id: config.clientId,
			client_secret: config.clientSecret,
			grant_type: "authorization_code",
			code,
			redirect_uri: outlookRedirectUri(c.req.raw),
			code_verifier: oauthState.codeVerifier,
			scope: OUTLOOK_SCOPES,
		});
		const response = await fetch(
			`https://login.microsoftonline.com/${config.tenant}/oauth2/v2.0/token`,
			{
				method: "POST",
				headers: { "content-type": "application/x-www-form-urlencoded" },
				body,
			},
		);
		if (!response.ok) throw new Error(`Microsoft token exchange failed (${response.status})`);
		const token = await response.json<{
			access_token: string;
			refresh_token?: string;
			expires_in: number;
			id_token: string;
		}>();
		if (!token.access_token || !token.refresh_token || !token.id_token)
			throw new Error("Microsoft did not return the required OAuth tokens");
		const identity = await verifyMicrosoftIdentity(
			token.id_token,
			config.clientId,
			oauthState.nonce,
		);

		await accountStore(c.env).add({
			name: oauthState.displayName,
			email: identity.email,
			imap: { host: "outlook.office365.com", port: 993, secure: true },
			smtp: { host: "smtp.office365.com", port: 587, secure: false },
			auth: {
				type: "oauth2",
				accessToken: token.access_token,
				refreshToken: token.refresh_token,
				clientId: config.clientId,
				tenant: config.tenant,
				expiresAt: Date.now() + token.expires_in * 1000,
			},
		});
		c.header("Set-Cookie", clearOauthCookie(c.req.url.startsWith("https://")));
		return c.redirect("/?status=outlook_connected", 303);
	} catch (error) {
		c.header("Set-Cookie", clearOauthCookie(c.req.url.startsWith("https://")));
		const accounts = await accountStore(c.env)
			.list()
			.catch(() => []);
		return c.html(
			managementPage(accounts, undefined, errorMessage(error), outlookConfigured(c.env), googleConfigured(c.env)),
			400,
		);
	}
});

app.post("/oauth/google/start", async (c) => {
	if (!isTrustedFormSubmission(c.req.raw)) return c.text("Forbidden", 403);

	try {
		const config = googleConfig(c.env);
		const form = await c.req.formData();
		const { oauthState, codeChallenge } = await createGoogleOAuthState(
			validName(required(form, "name")),
		);
		const redirectUri = googleRedirectUri(c.req.raw);
		const authorize = new URL("https://accounts.google.com/o/oauth2/v2/auth");
		authorize.search = new URLSearchParams({
			client_id: config.clientId,
			response_type: "code",
			redirect_uri: redirectUri,
			scope: GOOGLE_SCOPES,
			state: oauthState.state,
			nonce: oauthState.nonce,
			code_challenge: codeChallenge,
			code_challenge_method: "S256",
			access_type: "offline",
			prompt: "consent",
		}).toString();
		c.header(
			"Set-Cookie",
			oauthCookie(
				await sealJson(oauthState, c.env.CREDENTIAL_ENCRYPTION_KEY),
				c.req.url.startsWith("https://"),
				"google_oauth",
				"/oauth/google/callback",
			),
		);
		return c.redirect(authorize.toString(), 303);
	} catch (error) {
		const accounts = await accountStore(c.env)
			.list()
			.catch(() => []);
		return c.html(
			managementPage(
				accounts,
				undefined,
				errorMessage(error),
				outlookConfigured(c.env),
				googleConfigured(c.env),
			),
			400,
		);
	}
});

app.get("/oauth/google/callback", async (c) => {
	try {
		const config = googleConfig(c.env);
		const oauthError = c.req.query("error");
		if (oauthError) throw new Error(`Google authorization failed: ${oauthError}`);
		const code = c.req.query("code");
		const returnedState = c.req.query("state");
		const sealedState = cookieValue(c.req.raw, "google_oauth");
		if (!code || !returnedState || !sealedState)
			throw new Error("Google authorization expired");
		const oauthState = await openJson<GoogleOAuthState>(
			sealedState,
			c.env.CREDENTIAL_ENCRYPTION_KEY,
		);
		assertValidGoogleOAuthCallback(oauthState, returnedState);

		const body = new URLSearchParams({
			client_id: config.clientId,
			client_secret: config.clientSecret,
			grant_type: "authorization_code",
			code,
			redirect_uri: googleRedirectUri(c.req.raw),
			code_verifier: oauthState.codeVerifier,
		});
		const response = await fetch("https://oauth2.googleapis.com/token", {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body,
		});
		if (!response.ok) throw new Error(`Google token exchange failed (${response.status})`);
		const token = await response.json<{
			access_token: string;
			refresh_token?: string;
			expires_in: number;
			id_token: string;
		}>();
		if (!token.access_token || !token.id_token)
			throw new Error("Google did not return the required OAuth tokens");
		if (!token.refresh_token)
			throw new Error(
				"Google did not return a refresh token; remove this app's access in your Google account and sign in again",
			);
		const identity = await verifyGoogleIdentity(
			token.id_token,
			config.clientId,
			oauthState.nonce,
		);

		await accountStore(c.env).add({
			name: oauthState.displayName,
			email: identity.email,
			imap: { host: "imap.gmail.com", port: 993, secure: true },
			smtp: { host: "smtp.gmail.com", port: 465, secure: true },
			auth: {
				type: "oauth2",
				provider: "google",
				accessToken: token.access_token,
				refreshToken: token.refresh_token,
				clientId: config.clientId,
				expiresAt: Date.now() + token.expires_in * 1000,
			},
		});
		c.header(
			"Set-Cookie",
			clearOauthCookie(c.req.url.startsWith("https://"), "google_oauth", "/oauth/google/callback"),
		);
		return c.redirect("/?status=google_connected", 303);
	} catch (error) {
		c.header(
			"Set-Cookie",
			clearOauthCookie(c.req.url.startsWith("https://"), "google_oauth", "/oauth/google/callback"),
		);
		const accounts = await accountStore(c.env)
			.list()
			.catch(() => []);
		return c.html(
			managementPage(
				accounts,
				undefined,
				errorMessage(error),
				outlookConfigured(c.env),
				googleConfigured(c.env),
			),
			400,
		);
	}
});

app.get("/diagnostics/imap", async (c) => {
	try {
		const mail = new MailService(
			accountStore(c.env),
			{
				clientId: c.env.OUTLOOK_CLIENT_ID,
				clientSecret: c.env.OUTLOOK_CLIENT_SECRET,
			},
			{
				clientId: c.env.GOOGLE_CLIENT_ID,
				clientSecret: c.env.GOOGLE_CLIENT_SECRET,
			},
		);
		const connection = await mail.testConnection();
		const folders = await mail.listFolders();
		return c.json({ ...connection, folderCount: folders.length, folders });
	} catch (error) {
		return c.json({ error: errorMessage(error) }, 502);
	}
});

function accountStore(env: MailEnv): AccountStore {
	return new AccountStore(env.EMAIL_KV, env.CREDENTIAL_ENCRYPTION_KEY);
}

async function testNewAccount(
	env: MailEnv,
	account: Omit<MailAccount, "id">,
): Promise<{ smtpConfigured: boolean }> {
	const mail = new MailService(
		accountStore(env),
		{
			clientId: env.OUTLOOK_CLIENT_ID,
			clientSecret: env.OUTLOOK_CLIENT_SECRET,
		},
		{
			clientId: env.GOOGLE_CLIENT_ID,
			clientSecret: env.GOOGLE_CLIENT_SECRET,
		},
	);
	return mail.testAccount({ id: "pending", ...account });
}

async function pendingAccountChange(env: MailEnv, form: FormData): Promise<PendingAccountChange> {
	const sealed = requiredSecret(form, "pending");
	const pending = await openJson<PendingAccountChange>(sealed, env.CREDENTIAL_ENCRYPTION_KEY);
	if (
		(pending.mode !== "add" && pending.mode !== "update") ||
		!pending.account ||
		!pending.createdAt ||
		Date.now() - pending.createdAt > 10 * 60_000 ||
		(pending.mode === "update" && !pending.accountId)
	)
		throw new Error("Pending account expired; enter the account details again");
	return pending;
}

async function persistAccountChange(env: MailEnv, pending: PendingAccountChange): Promise<void> {
	const store = accountStore(env);
	if (pending.mode === "add") {
		await store.add(pending.account);
		return;
	}
	await store.update({ id: pending.accountId!, ...pending.account });
}

async function accountTestFailureResponse(
	c: MailContext,
	error: unknown,
	pending: PendingAccountChange,
) {
	const accounts = await accountStore(c.env)
		.list()
		.catch(() => []);
	const sealed = await sealJson(pending, c.env.CREDENTIAL_ENCRYPTION_KEY);
	return c.html(
		managementPage(accounts, undefined, undefined, outlookConfigured(c.env), googleConfigured(c.env), undefined, {
			message: errorMessage(error),
			pending: sealed,
			change: pending,
		}),
		502,
	);
}

async function pendingAccountError(c: MailContext, error: unknown) {
	const accounts = await accountStore(c.env)
		.list()
		.catch(() => []);
	return c.html(
		managementPage(accounts, undefined, errorMessage(error), outlookConfigured(c.env), googleConfigured(c.env)),
		400,
	);
}

function providerKey(
	account: MailAccount,
): "gmail" | "icloud" | "outlook" | "yahoo" | "aol" | "qq" | "netease163" | "netease126" | "exmail" | "fastmail" | "zoho" | "custom" {
	if ((account.auth.type === "oauth2" && account.auth.provider === "google") || account.imap.host === "imap.gmail.com")
		return "gmail";
	if (account.imap.host === "imap.mail.me.com") return "icloud";
	if (account.imap.host === "outlook.office365.com") return "outlook";
	if (account.imap.host === "imap.mail.yahoo.com") return "yahoo";
	if (account.imap.host === "imap.aol.com") return "aol";
	if (account.imap.host === "imap.qq.com") return "qq";
	if (account.imap.host === "imap.163.com") return "netease163";
	if (account.imap.host === "imap.126.com") return "netease126";
	if (account.imap.host === "imap.exmail.qq.com") return "exmail";
	if (account.imap.host === "imap.fastmail.com") return "fastmail";
	if (account.imap.host === "imap.zoho.com") return "zoho";
	return "custom";
}

function providerLabel(account: MailAccount): string {
	const labels: Record<ReturnType<typeof providerKey>, string> = {
		gmail: "Gmail",
		icloud: "iCloud",
		outlook: "Outlook",
		yahoo: "Yahoo",
		aol: "AOL",
		qq: "QQ邮箱",
		netease163: "163邮箱",
		netease126: "126邮箱",
		exmail: "腾讯企业邮",
		fastmail: "Fastmail",
		zoho: "Zoho",
		custom: "Custom",
	};
	return labels[providerKey(account)];
}

function managementPage(
	accounts: MailAccount[],
	status?: string,
	error?: string,
	outlookOAuthConfigured = false,
	googleOAuthConfigured = false,
	editAccount?: MailAccount,
	accountTestFailure?: {
		message: string;
		pending: string;
		change: PendingAccountChange;
	},
	hasAdminSession = false,
): string {
	const testSuccess =
		status === "added_tested"
			? {
					title: "Connection test successful",
					message:
						"IMAP and SMTP authentication both passed. The account has been saved.",
				}
			: status === "updated_tested"
				? {
						title: "Connection test successful",
						message:
							"IMAP and SMTP authentication both passed. The account changes have been saved.",
					}
				: status === "added_tested_imap_only"
					? {
							title: "Connection test successful",
							message:
								"IMAP authentication passed and the account has been saved. SMTP is not configured, so this account cannot send email.",
						}
					: status === "updated_tested_imap_only"
						? {
								title: "Connection test successful",
								message:
									"IMAP authentication passed and the account changes have been saved. SMTP is not configured, so this account cannot send email.",
							}
						: status === "connection_imap_only"
							? {
									title: "Connection test successful",
									message:
										"IMAP authentication passed. SMTP is not configured, so this account cannot send email.",
								}
							: status === "connection_ok"
								? {
										title: "Connection test successful",
										message: "IMAP and SMTP authentication both passed.",
									}
								: undefined;
	const notice =
		status === "added"
			? '<div class="notice success" role="status">Account added.</div>'
			: status === "added_untested"
				? '<div class="notice success" role="status">Account saved without a successful connection test.</div>'
				: status === "updated_untested"
					? '<div class="notice success" role="status">Account changes saved without a successful connection test.</div>'
					: status === "outlook_connected"
						? '<div class="notice success" role="status">Outlook account connected.</div>'
						: status === "google_connected"
							? '<div class="notice success" role="status">Google account connected.</div>'
						: status === "updated"
							? '<div class="notice success" role="status">Account settings updated.</div>'
							: status === "removed"
								? '<div class="notice success" role="status">Account removed.</div>'
								: error
									? `<div class="notice error" role="alert">${escapeHtml(error)}</div>`
									: "";
	const rows = accounts.length
		? accounts
				.map(
					(account) => `<li class="account">
						<div class="account-header">
							<div class="account-identity"><span class="account-avatar avatar-${providerKey(account)}" aria-hidden="true">${escapeHtml(account.name.charAt(0).toUpperCase())}</span><div><strong>${escapeHtml(account.name)}</strong><span>${escapeHtml(account.email)}</span><span class="badges"><span class="badge">${providerLabel(account)}</span><span class="badge${account.auth.type === "oauth2" ? " badge-oauth" : ""}">${account.auth.type === "oauth2" ? "OAuth 2.0" : "Password"}</span>${account.smtp ? "" : '<span class="badge">Receive only</span>'}</span></div></div>
							<div class="account-actions">
								<a class="secondary action-link" href="/?edit=${encodeURIComponent(account.id)}">Edit</a>
								<form method="post" action="/accounts/${encodeURIComponent(account.id)}/test">
									<button class="secondary" type="submit">Test connection</button>
								</form>
								<form method="post" action="/accounts/${encodeURIComponent(account.id)}/remove" onsubmit="return confirm('Remove this account?')">
									<button class="danger" type="submit">Remove</button>
								</form>
							</div>
						</div>
						<details class="account-details">
							<summary>Connection settings</summary>
							<dl class="account-settings">
								<div><dt>IMAP</dt><dd>${escapeHtml(account.imap.host)}:${account.imap.port}<button type="button" class="copy-btn" data-copy="${escapeHtml(account.imap.host)}:${account.imap.port}">Copy</button></dd></div>
								<div><dt>IMAP security</dt><dd>${account.imap.secure ? "Implicit TLS" : "STARTTLS"}</dd></div>
								<div><dt>SMTP</dt><dd>${account.smtp ? `${escapeHtml(account.smtp.host)}:${account.smtp.port}` : "Not configured"}${account.smtp ? `<button type="button" class="copy-btn" data-copy="${escapeHtml(account.smtp.host)}:${account.smtp.port}">Copy</button>` : ""}</dd></div>
								${account.smtp ? `<div><dt>SMTP security</dt><dd>${account.smtp.secure ? "Implicit TLS" : "STARTTLS"}</dd></div>` : ""}
								<div><dt>Can send</dt><dd>${account.smtp ? "Yes" : "No"}</dd></div>
								<div><dt>Authentication</dt><dd>${account.auth.type === "oauth2" ? "OAuth 2.0" : "Password"}</dd></div>
								<div><dt>Default From</dt><dd>${escapeHtml(account.defaultFrom ?? account.email)}</dd></div>
								<div><dt>Aliases</dt><dd>${escapeHtml(account.aliases?.join(", ") || "None configured")}</dd></div>
							</dl>
						</details>
					</li>`,
				)
				.join("")
		: '<li class="empty"><strong>No email accounts yet</strong>Use the Add account button above to connect your first mailbox.</li>';
	const editor = accountEditor(
		editAccount,
		outlookOAuthConfigured,
		googleOAuthConfigured,
		accountTestFailure?.change,
		accountTestFailure?.pending,
	);
	const testFailure = accountTestFailure
		? `<dialog class="account-dialog test-failure-dialog" id="test-failure-dialog" aria-labelledby="test-failure-heading">
		<section class="dialog-card">
			<div class="test-failure-icon" aria-hidden="true">!</div>
			<h2 id="test-failure-heading">Connection test failed</h2>
			<p>The account has not been saved. Check the error and choose what to do next.</p>
			<div class="test-error" role="alert">${escapeHtml(accountTestFailure.message)}</div>
			<div class="test-actions">
				<form method="post" action="/accounts/pending/retry"><input type="hidden" name="pending" value="${escapeHtml(accountTestFailure.pending)}"><button type="submit">Run test again</button></form>
				<button class="secondary" id="edit-failed-account" type="button">Edit details</button>
				<form method="post" action="/accounts/pending/save"><input type="hidden" name="pending" value="${escapeHtml(accountTestFailure.pending)}"><button class="secondary" type="submit">Save anyway</button></form>
				<form method="post" action="/accounts/pending/cancel"><button class="plain-button" type="submit">Cancel</button></form>
			</div>
		</section>
	</dialog>`
		: "";
	const testSuccessDialog = testSuccess
		? `<dialog class="account-dialog test-result-dialog" id="test-success-dialog" aria-labelledby="test-success-heading">
		<section class="dialog-card">
			<div class="test-success-icon" aria-hidden="true">✓</div>
			<h2 id="test-success-heading">${testSuccess.title}</h2>
			<p>${testSuccess.message}</p>
			<button class="test-result-close" id="test-success-close" type="button">Done</button>
		</section>
	</dialog>`
		: "";

	return `<!doctype html>
	<html lang="en">
		<head>
			<meta charset="utf-8">
			<meta name="viewport" content="width=device-width, initial-scale=1">
			<meta name="referrer" content="no-referrer">
			<title>Email account management</title>
		<link rel="icon" type="image/svg+xml" href="/logo.svg">
						<style>
				:root { color-scheme: light dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; color: #172033; background: #eef1f7; --surface: #fff; --surface-soft: #f7f9fc; --border: #dfe3eb; --border-strong: #bdc4d0; --text: #172033; --muted: #5d6678; --faint: #747d8f; --accent: #245fc2; --accent-hover: #194c9f; --accent-soft: #edf3ff; --accent-ring: #c9dcff; --success-text: #146c43; --success-bg: #eaf8f0; --success-border: #bce7ce; --danger-text: #9b2c2c; --danger-bg: #fff0f0; --danger-border: #f0bcbc; --danger-button-text: #a12e2e; --danger-button-hover: #f8dada; --chip-bg: #eef1f6; --shadow: 0 8px 28px rgba(23,32,51,.06); --dialog-shadow: 0 24px 70px rgba(23,32,51,.28); }
				@media (prefers-color-scheme: dark) { :root { color: #e7ecf5; background: #0b1120; --surface: #141c2e; --surface-soft: #1a2438; --border: #273350; --border-strong: #3a4a6e; --text: #e7ecf5; --muted: #9aa7bf; --faint: #7e8ca6; --accent: #6ea8ff; --accent-hover: #8fbcff; --accent-soft: #1c2c4d; --accent-ring: #33507f; --success-text: #5fd598; --success-bg: #123324; --success-border: #1f5138; --danger-text: #ff9c9c; --danger-bg: #3d1a1a; --danger-border: #662b2b; --danger-button-text: #ff9c9c; --danger-button-hover: #4d2222; --chip-bg: #1e2a44; --shadow: 0 8px 28px rgba(0,0,0,.35); --dialog-shadow: 0 24px 70px rgba(0,0,0,.6); } }
				* { box-sizing: border-box; }
				body { margin: 0; background: radial-gradient(60rem 30rem at 85% -10%, rgba(57,118,215,.14), transparent 60%), radial-gradient(50rem 26rem at -10% 0%, rgba(57,118,215,.10), transparent 55%); min-height: 100vh; }
				main { width: min(58rem, calc(100% - 2rem)); margin: 3rem auto; }
				header { margin-bottom: 1.5rem; }
				.page-header, .section-heading, .dialog-heading { display: flex; gap: 1rem; align-items: center; justify-content: space-between; }
				.page-header > div, .dialog-heading > div { min-width: 0; }
				.brand { display: flex; gap: .85rem; align-items: center; }
				.brand-mark { flex: 0 0 auto; width: 3rem; height: 3rem; border-radius: .85rem; display: block; box-shadow: 0 6px 16px rgba(36,95,194,.35); }
				h1, h2 { margin: 0 0 .5rem; line-height: 1.2; }
				h1 { font-size: clamp(1.75rem, 5vw, 2.5rem); letter-spacing: -.02em; }
				.brand h1 { margin-bottom: .15rem; }
				p { margin: 0; color: var(--muted); }
				.card { background: var(--surface); border: 1px solid var(--border); border-radius: .9rem; padding: 1.4rem; box-shadow: var(--shadow); }
				.notice { margin: 0 0 1.25rem; padding: .8rem 1rem; border-radius: .6rem; animation: notice-in .25s ease; transition: opacity .4s ease, transform .4s ease; }
				.notice-hide { opacity: 0; transform: translateY(-4px); }
				@keyframes notice-in { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: none; } }
				.success { color: var(--success-text); background: var(--success-bg); border: 1px solid var(--success-border); }
				.error { color: var(--danger-text); background: var(--danger-bg); border: 1px solid var(--danger-border); }
				.count { display: inline-flex; align-items: center; justify-content: center; min-width: 1.75rem; height: 1.75rem; padding: 0 .5rem; border-radius: 999px; color: var(--muted); background: var(--chip-bg); font-size: .8rem; font-weight: 700; }
				.accounts { list-style: none; padding: 0; margin: .85rem 0 0; }
				.account { padding: 1.1rem 0; border-top: 1px solid var(--border); }
				.account:first-child { border-top: 0; }
				.account span { display: block; color: var(--muted); overflow-wrap: anywhere; }
				.account-header { display: flex; gap: 1rem; align-items: center; justify-content: space-between; }
				.account-identity { display: flex; min-width: 0; gap: .75rem; align-items: center; }
				.account-avatar { display: grid !important; flex: 0 0 auto; width: 2.5rem; height: 2.5rem; place-items: center; border-radius: .65rem; color: #245fc2 !important; background: #edf3ff; font-weight: 800; }
				.account-avatar.avatar-gmail { color: #b3261e !important; background: #fdecea; }
				.account-avatar.avatar-icloud { color: #3a3a3c !important; background: #ececf0; }
				.account-avatar.avatar-yahoo { color: #6001d2 !important; background: #f0e9fd; }
				.account-avatar.avatar-aol { color: #005eb8 !important; background: #e5f1fb; }
				.account-avatar.avatar-qq { color: #0e7fd6 !important; background: #e3f4fd; }
				.account-avatar.avatar-netease163 { color: #c62828 !important; background: #fdecea; }
				.account-avatar.avatar-netease126 { color: #2f9e44 !important; background: #e6f6e8; }
				.account-avatar.avatar-exmail { color: #0052d9 !important; background: #e5eefc; }
				.account-avatar.avatar-fastmail { color: #1f4e79 !important; background: #e8f0f8; }
				.account-avatar.avatar-zoho { color: #d61f26 !important; background: #fdecec; }
				.account-avatar.avatar-outlook { color: #0f4c9c !important; background: #e3eefc; }
				@media (prefers-color-scheme: dark) { .account-avatar.avatar-gmail { color: #ff9c94 !important; background: #3d1f1c; } .account-avatar.avatar-icloud { color: #d6d6da !important; background: #2c2f36; } .account-avatar.avatar-outlook { color: #8fbcff !important; background: #16294d; } .account-avatar.avatar-yahoo { color: #c4a6ff !important; background: #2a1650; } .account-avatar.avatar-aol { color: #8fc3ff !important; background: #12325a; } .account-avatar.avatar-qq { color: #7cc7ff !important; background: #10344d; } .account-avatar.avatar-netease163 { color: #ff9e99 !important; background: #38150f; } .account-avatar.avatar-netease126 { color: #8fe388 !important; background: #14351a; } .account-avatar.avatar-exmail { color: #8fb4ff !important; background: #122c52; } .account-avatar.avatar-fastmail { color: #9cc3e8 !important; background: #14283d; } .account-avatar.avatar-zoho { color: #ff9c9c !important; background: #3d1618; } }
				.badges { display: flex !important; flex-wrap: wrap; gap: .35rem; margin-top: .35rem; }
				.badge { display: inline-flex !important; align-items: center; padding: .12rem .5rem; border-radius: 999px; color: var(--muted) !important; background: var(--chip-bg); font-size: .72rem; font-weight: 700; letter-spacing: .01em; }
				.badge-oauth { color: var(--success-text) !important; background: var(--success-bg); }
				.account-details { margin-top: .75rem; }
				.account-details summary { display: flex; width: fit-content; gap: .4rem; align-items: center; list-style: none; cursor: pointer; color: var(--accent); font-size: .85rem; font-weight: 700; }
				.account-details summary::-webkit-details-marker { display: none; }
				.account-details summary::before { content: "›"; font-size: 1.2rem; line-height: .8; transition: transform .15s ease; }
				.account-details[open] summary::before { transform: rotate(90deg); }
				.account-details summary:hover { color: var(--accent-hover); }
				.account-settings { display: grid; grid-template-columns: 1fr 1fr; gap: .65rem 1.5rem; margin: .8rem 0 0; padding: .85rem 1rem; border-radius: .6rem; color: var(--muted); background: var(--surface-soft); font-size: .85rem; }
				.account-settings div { display: grid; grid-template-columns: minmax(6.5rem, 8rem) minmax(0, 1fr); gap: .5rem; }
				.account-settings dt { color: var(--faint); }
				.account-settings dd { display: flex; min-width: 0; margin: 0; gap: .5rem; align-items: center; overflow-wrap: anywhere; }
				.copy-btn { flex: 0 0 auto; padding: .15rem .5rem; border-radius: .35rem; color: var(--accent); background: var(--accent-soft); font-size: .72rem; font-weight: 700; }
				.copy-btn:hover { background: var(--accent-ring); }
				.account-actions { display: flex; flex: 0 0 auto; gap: .5rem; }
				.account-actions button, .account-actions a { white-space: nowrap; }
				.empty { color: var(--faint); padding: 1.5rem 0 .75rem; text-align: center; }
				.empty strong { display: block; margin-bottom: .35rem; color: var(--muted); font-size: 1rem; }
				fieldset { border: 0; margin: 1.25rem 0 0; padding: 0; }
				legend { font-weight: 700; margin-bottom: .75rem; }
				.fieldset-heading { display: flex; width: 100%; gap: 1rem; align-items: center; justify-content: space-between; }
				.smtp-toggle { display: flex; gap: .45rem; align-items: center; color: var(--muted); font-size: .83rem; font-weight: 700; }
				.fields { display: grid; grid-template-columns: 1fr 1fr; gap: .9rem; }
				.server-fields { grid-template-columns: minmax(0, 2fr) minmax(6.5rem, 1fr) auto; align-items: end; }
				.account-detail-fields > .fields:first-child { margin-top: 1.25rem; }
				#manual-account-fields > .fields:first-child { margin-top: .9rem; }
				.provider-picker { margin-top: 1.25rem; }
				.provider-options { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: .65rem; }
				.provider-option { display: grid; min-height: 4.25rem; padding: .75rem .5rem; gap: .3rem; place-items: center; border: 1px solid var(--border-strong); color: var(--text); background: var(--surface); transition: border-color .15s ease, background .15s ease, transform .1s ease; }
				.provider-option:hover { border-color: #3976d7; color: var(--accent); background: var(--accent-soft); }
				.provider-option:active { transform: scale(.98); }
				.provider-option[aria-pressed="true"] { border-color: var(--accent); outline: 3px solid var(--accent-ring); color: var(--accent); background: var(--accent-soft); }
				.provider-mark { display: grid; width: 2rem; height: 2rem; place-items: center; border-radius: .55rem; color: #fff; font-weight: 800; font-size: .95rem; }
				.provider-mark.mark-gmail { background: #d93025; }
				.provider-mark.mark-icloud { background: #55555c; }
				.provider-mark.mark-outlook { background: #0f6cbd; }
				.provider-mark.mark-yahoo { background: #6001d2; }
				.provider-mark.mark-aol { background: #0072bc; }
				.provider-mark.mark-qq { background: #0099e5; }
				.provider-mark.mark-netease163 { background: #d33a31; }
				.provider-mark.mark-netease126 { background: #35a03f; }
				.provider-mark.mark-exmail { background: #0052d9; }
				.provider-mark.mark-fastmail { background: #1f4e79; }
				.provider-mark.mark-zoho { background: #e4252b; }
				.provider-mark.mark-num { font-size: .68rem; letter-spacing: -.02em; }
				.provider-mark.mark-custom { background: #747d8f; }
				.provider-name { font-weight: 700; font-size: .92rem; line-height: 1.1; }
				.provider-sub { color: var(--faint); font-size: .72rem; font-weight: 600; line-height: 1.1; }
				label { display: grid; gap: .35rem; color: var(--text); font-size: .9rem; font-weight: 600; }
				.full { grid-column: 1 / -1; }
				input, select, button { font: inherit; }
				input:not([type="checkbox"]), select { width: 100%; height: 2.75rem; padding: .7rem .75rem; color: var(--text); background: var(--surface); border: 1px solid var(--border-strong); border-radius: .45rem; }
				input:not([type="checkbox"]):focus, select:focus { outline: 3px solid var(--accent-ring); border-color: #3976d7; }
				button:focus-visible, a:focus-visible, summary:focus-visible { outline: 3px solid var(--accent-ring); outline-offset: 2px; }
				.check { display: flex; gap: .5rem; align-items: center; align-self: end; min-height: 2.65rem; }
				.check input { width: auto; }
				button { cursor: pointer; padding: .7rem 1rem; border: 0; border-radius: .45rem; background: var(--accent); color: #fff; font-weight: 700; transition: background .15s ease, transform .1s ease; }
				button:hover { background: var(--accent-hover); }
				button:active { transform: scale(.98); }
				button:disabled { cursor: not-allowed; opacity: .55; }
				button[data-loading="true"]::before { content: ""; display: inline-block; width: .85em; height: .85em; margin-right: .5em; vertical-align: -.1em; border: 2px solid currentColor; border-top-color: transparent; border-radius: 50%; animation: spin .7s linear infinite; }
				@keyframes spin { to { transform: rotate(360deg); } }
				.primary-action { flex: 0 0 auto; box-shadow: 0 4px 12px rgba(36,95,194,.2); }
				.header-actions { display: flex; gap: .5rem; align-items: center; }
				.logout-form { margin: 0; display: flex; }
				.secondary { padding: .5rem .75rem; border: 0; border-radius: .45rem; color: var(--accent); background: var(--accent-soft); font-weight: 700; }
				.secondary:hover { background: var(--accent-ring); }
				.action-link { display: inline-flex; align-items: center; text-decoration: none; }
				.danger { padding: .5rem .75rem; color: var(--danger-button-text); background: var(--danger-bg); }
				.danger:hover { background: var(--danger-button-hover); }
				.submit { margin-top: 1.25rem; }
				.form-actions { display: flex; gap: .75rem; align-items: center; margin-top: 1.25rem; }
				.form-actions .submit { margin: 0; }
				.cancel-link { color: var(--muted); font-weight: 700; text-decoration: none; }
				.cancel-link:hover { color: var(--text); text-decoration: underline; }
				.help { margin-top: .8rem; font-size: .83rem; }
				.account-dialog { width: min(42rem, calc(100% - 2rem)); max-height: calc(100vh - 2rem); margin: auto; padding: 0; overflow: auto; border: 0; border-radius: 1rem; color: inherit; background: transparent; box-shadow: var(--dialog-shadow); }
				.account-dialog[open] { animation: dialog-in .22s ease; }
				@keyframes dialog-in { from { opacity: 0; transform: translateY(10px) scale(.99); } to { opacity: 1; transform: none; } }
				.account-dialog::backdrop { background: rgba(23,32,51,.5); backdrop-filter: blur(3px); }
				.dialog-card { padding: 1.5rem; background: var(--surface); }
				.dialog-heading { padding-bottom: 1rem; border-bottom: 1px solid var(--border); }
				.dialog-heading h2 { margin-bottom: .25rem; }
				.icon-button { display: grid; flex: 0 0 auto; width: 2.25rem; height: 2.25rem; padding: 0; place-items: center; border-radius: 999px; color: var(--muted); background: var(--chip-bg); font-size: 1.35rem; }
				.icon-button:hover { color: var(--text); background: var(--border); }
				.test-failure-dialog { width: min(34rem, calc(100% - 2rem)); }
				.test-failure-dialog .dialog-card, .test-result-dialog .dialog-card { text-align: center; }
				.test-failure-icon { display: grid; width: 3rem; height: 3rem; margin: 0 auto 1rem; place-items: center; border-radius: 999px; color: var(--danger-text); background: var(--danger-bg); font-size: 1.5rem; font-weight: 800; }
				.test-result-dialog { width: min(34rem, calc(100% - 2rem)); }
				.test-success-icon { display: grid; width: 3rem; height: 3rem; margin: 0 auto 1rem; place-items: center; border-radius: 999px; color: var(--success-text); background: var(--success-bg); font-size: 1.5rem; font-weight: 800; }
				.test-result-close { margin-top: 1.25rem; min-width: 7rem; }
				.test-error { margin: 1rem 0; padding: .85rem 1rem; border-radius: .6rem; color: var(--danger-text); background: var(--danger-bg); overflow-wrap: anywhere; text-align: left; }
				.test-actions { display: flex; gap: .65rem; justify-content: center; flex-wrap: wrap; }
				.plain-button { color: var(--muted); background: transparent; }
				.plain-button:hover { color: var(--text); background: var(--chip-bg); }
				[hidden] { display: none !important; }
				@media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation-duration: .01ms !important; transition-duration: .01ms !important; } }
				@media (max-width: 760px) { main { margin: 1.5rem auto; } .fields, .account-settings { grid-template-columns: 1fr; } .full { grid-column: auto; } }
				@media (max-width: 560px) { .page-header, .account-header { align-items: stretch; flex-direction: column; } .primary-action { width: 100%; } .account-actions { display: grid; grid-template-columns: 1fr 1fr; } .account-actions > :last-child { grid-column: 1 / -1; } .account-actions button, .account-actions a { justify-content: center; width: 100%; } .account-settings div { grid-template-columns: 1fr; gap: .1rem; } .provider-options { grid-template-columns: 1fr 1fr; } }
			</style>
		</head>
		<body>
			<main>
				<header class="page-header"><div class="brand"><img class="brand-mark" src="/logo.svg" alt="" aria-hidden="true"><div><h1>Email accounts</h1><p>Manage the mailboxes available to your MCP server.</p></div></div><div class="header-actions">${hasAdminSession ? '<form method="post" action="/logout" class="logout-form"><button class="secondary" type="submit">Sign out</button></form>' : ""}<button class="primary-action" id="add-account-button" type="button">＋ Add account</button></div></header>
				${notice}
				<section class="card" aria-labelledby="configured-heading">
					<div class="section-heading"><h2 id="configured-heading">Configured accounts</h2><span class="count" aria-label="${accounts.length} configured accounts">${accounts.length}</span></div>
						<ul class="accounts">${rows}</ul>
				</section>
				${editor.html}
				${testFailure}
				${testSuccessDialog}
			</main>
			${editor.script}
			${accountTestFailure ? '<script>const testFailureDialog = document.getElementById("test-failure-dialog"); testFailureDialog.addEventListener("cancel", (event) => event.preventDefault()); document.getElementById("edit-failed-account").addEventListener("click", () => { testFailureDialog.close(); document.getElementById("account-editor").showModal(); }); testFailureDialog.showModal();</script>' : ""}
			${testSuccess ? '<script>const testSuccessDialog = document.getElementById("test-success-dialog"); document.getElementById("test-success-close").addEventListener("click", () => testSuccessDialog.close()); testSuccessDialog.showModal();</script>' : ""}
			<script>const statusUrl = new URL(window.location.href); if (statusUrl.searchParams.has("status")) { statusUrl.searchParams.delete("status"); history.replaceState(null, "", statusUrl.pathname + statusUrl.search + statusUrl.hash); }
			document.querySelectorAll(".notice.success").forEach((notice) => { setTimeout(() => { notice.classList.add("notice-hide"); setTimeout(() => notice.remove(), 450); }, 6000); });
			document.querySelectorAll("[data-copy]").forEach((button) => { button.addEventListener("click", async () => { try { await navigator.clipboard.writeText(button.dataset.copy); const original = button.textContent; button.textContent = "Copied"; setTimeout(() => { button.textContent = original; }, 1500); } catch { button.textContent = "Copy failed"; } }); });
			document.addEventListener("submit", (event) => { const submitter = event.submitter; if (submitter && submitter.tagName === "BUTTON" && !submitter.disabled) { submitter.dataset.loading = "true"; submitter.disabled = true; event.target.querySelectorAll("button").forEach((button) => { if (button !== submitter) button.disabled = true; }); } });
			</script>
		</body>
	</html>`;
}

function accountEditor(
	account?: MailAccount,
	outlookOAuthConfigured = false,
	googleOAuthConfigured = false,
	pendingChange?: PendingAccountChange,
	pendingToken?: string,
): { html: string; script: string } {
	const editing = Boolean(account || pendingChange);
	const existingAccount = pendingChange ? pendingChange.mode === "update" : Boolean(account);
	const autoOpen = Boolean(account && !pendingChange);
	const formAccount = pendingChange
		? { id: pendingChange.accountId ?? "pending", ...pendingChange.account }
		: account;
	const html = `<dialog class="account-dialog" id="account-editor" aria-labelledby="account-editor-heading">
	<section class="dialog-card">
		<div class="dialog-heading"><div><h2 id="account-editor-heading">${pendingChange ? "Edit account details" : editing ? "Edit account" : "Add an account"}</h2><p>${pendingChange ? "The credential from the failed test is preserved securely." : editing ? "Update the mailbox connection settings." : "Choose a provider and enter the account details."}</p></div><button class="icon-button" type="button" data-dialog-close aria-label="Close">×</button></div>
		<form method="post" action="${pendingChange ? "/accounts/pending/edit-test" : editing ? `/accounts/${encodeURIComponent(account!.id)}/update` : "/accounts"}" autocomplete="off" id="account-form">
			${pendingToken ? `<input type="hidden" name="pending" value="${escapeHtml(pendingToken)}">` : ""}
			${
				editing
					? ""
					: `<fieldset class="provider-picker"><legend>Provider</legend><div class="provider-options" role="group" aria-label="Email provider">
				<button class="provider-option" type="button" data-provider="gmail" aria-pressed="false"><span class="provider-mark mark-gmail" aria-hidden="true">G</span><span class="provider-name">Gmail</span><span class="provider-sub">Google</span></button>
				<button class="provider-option" type="button" data-provider="icloud" aria-pressed="false"><span class="provider-mark mark-icloud" aria-hidden="true">i</span><span class="provider-name">iCloud</span><span class="provider-sub">Apple</span></button>
				<button class="provider-option" type="button" data-provider="outlook" aria-pressed="false"><span class="provider-mark mark-outlook" aria-hidden="true">O</span><span class="provider-name">Outlook</span><span class="provider-sub">Microsoft</span></button>
				<button class="provider-option" type="button" data-provider="yahoo" aria-pressed="false"><span class="provider-mark mark-yahoo" aria-hidden="true">Y</span><span class="provider-name">Yahoo</span><span class="provider-sub">Yahoo Mail</span></button>
				<button class="provider-option" type="button" data-provider="aol" aria-pressed="false"><span class="provider-mark mark-aol" aria-hidden="true">A</span><span class="provider-name">AOL</span><span class="provider-sub">AOL Mail</span></button>
				<button class="provider-option" type="button" data-provider="qq" aria-pressed="false"><span class="provider-mark mark-qq" aria-hidden="true">Q</span><span class="provider-name">QQ邮箱</span><span class="provider-sub">腾讯</span></button>
				<button class="provider-option" type="button" data-provider="netease163" aria-pressed="false"><span class="provider-mark mark-netease163 mark-num" aria-hidden="true">163</span><span class="provider-name">163邮箱</span><span class="provider-sub">网易</span></button>
				<button class="provider-option" type="button" data-provider="netease126" aria-pressed="false"><span class="provider-mark mark-netease126 mark-num" aria-hidden="true">126</span><span class="provider-name">126邮箱</span><span class="provider-sub">网易</span></button>
				<button class="provider-option" type="button" data-provider="exmail" aria-pressed="false"><span class="provider-mark mark-exmail" aria-hidden="true">企</span><span class="provider-name">腾讯企业邮</span><span class="provider-sub">Exmail</span></button>
				<button class="provider-option" type="button" data-provider="fastmail" aria-pressed="false"><span class="provider-mark mark-fastmail" aria-hidden="true">F</span><span class="provider-name">Fastmail</span><span class="provider-sub">Fastmail</span></button>
				<button class="provider-option" type="button" data-provider="zoho" aria-pressed="false"><span class="provider-mark mark-zoho" aria-hidden="true">Z</span><span class="provider-name">Zoho</span><span class="provider-sub">Zoho Mail</span></button>
				<button class="provider-option" type="button" data-provider="custom" aria-pressed="false"><span class="provider-mark mark-custom" aria-hidden="true">@</span><span class="provider-name">Custom</span><span class="provider-sub">IMAP / SMTP</span></button>
			</div></fieldset>`
			}
			<div class="account-detail-fields" id="account-detail-fields"${editing ? "" : " hidden"}>
			<div class="fields">
				<label class="full">Display name<input name="name" value="${escapeHtml(formAccount?.name ?? "")}" required maxlength="100" autocomplete="off"></label>
			</div>
			<div id="manual-account-fields">
			<div class="fields">
				<label class="full">Login email address<input name="email" type="email" value="${escapeHtml(formAccount?.email ?? "")}" required maxlength="320" autocomplete="username"></label>
			</div>
			<fieldset><legend>Sender addresses</legend><div class="fields">
				<label class="full">Email aliases<input name="aliases" value="${escapeHtml(formAccount?.aliases?.join(", ") ?? "")}" placeholder="alias@icloud.com, alias@outlook.com" autocomplete="off"></label>
				<label class="full">Default From address<input name="defaultFrom" type="email" value="${escapeHtml(formAccount?.defaultFrom ?? "")}" placeholder="Defaults to login email address" maxlength="320" autocomplete="off"></label>
			</div><p class="help">Enter aliases for this mailbox separated by commas. The default From must be the login email or one of these aliases. Only add addresses your provider already allows this account to send from. These settings apply to new drafts and replies; existing drafts keep their saved sender.</p></fieldset>
			<fieldset><legend>Incoming mail (IMAP)</legend><div class="fields server-fields">
				<label>Host<input name="imapHost" id="imap-host" value="${escapeHtml(formAccount?.imap.host ?? "")}" required></label>
				<label>Port<input name="imapPort" id="imap-port" type="number" min="1" max="65535" value="${formAccount?.imap.port ?? ""}" placeholder="993" required></label>
				<label class="check" title="Use implicit TLS"><input name="imapSecure" id="imap-secure" type="checkbox"${formAccount?.imap.secure === false ? "" : " checked"}> TLS</label>
			</div></fieldset>
			<fieldset><legend class="fieldset-heading"><span>Outgoing mail (SMTP)</span><label class="smtp-toggle"><input name="smtpEnabled" id="smtp-enabled" type="checkbox"${formAccount?.smtp ? " checked" : ""}> Enable SMTP</label></legend><div class="fields server-fields" id="smtp-fields"${formAccount?.smtp ? "" : " hidden"}>
				<label>Host<input name="smtpHost" id="smtp-host" value="${escapeHtml(formAccount?.smtp?.host ?? "")}" required></label>
				<label>Port<input name="smtpPort" id="smtp-port" type="number" min="1" max="65535" value="${formAccount?.smtp?.port ?? ""}" placeholder="587" required></label>
				<label class="check" title="Use implicit TLS"><input name="smtpSecure" id="smtp-secure" type="checkbox"${formAccount?.smtp?.secure === false ? "" : " checked"}> TLS</label>
			</div></fieldset>
			${
				editing
					? ""
					: `<fieldset><legend>Authentication</legend><div class="fields">
				<label class="full" id="auth-type-field">Type<select name="authType" id="auth-type"><option value="password">App password</option><option value="oauth2">OAuth 2.0 tokens</option></select></label>
				<label class="full" id="password-field">App password<input name="password" id="password" type="password" autocomplete="new-password"></label>
				<div class="fields full" id="oauth-fields" hidden>
					<label class="full">Access token<input name="accessToken" id="access-token" type="password" autocomplete="off"></label>
					<label class="full">Refresh token<input name="refreshToken" type="password" autocomplete="off"></label>
					<label>Client ID<input name="oauthClientId" autocomplete="off"></label>
					<label>Tenant<input name="oauthTenant" value="consumers" autocomplete="off"></label>
				</div>
			</div></fieldset>`
			}
			</div>
			<div class="form-actions">
				<button class="submit" id="account-submit" type="submit">${existingAccount ? "Save changes" : "Test and save account"}</button>
				${editing ? '<a class="cancel-link" href="/">Cancel</a>' : '<button class="secondary" type="button" data-dialog-close>Cancel</button>'}
			</div>
			<p class="help" id="account-help">${pendingChange ? "Change the connection details and test again. The stored pending credential is never returned to the page." : editing ? "Changing the login email changes the IMAP and SMTP username. Use Default From to change your sender instead. Connection changes are tested before saving; sender-only changes keep your credentials and need no connection test." : "Most providers require an app password or authorization code from the provider's security settings, not your normal sign-in password. Passwords and tokens are never displayed after saving."}</p>
			</div>
		</form>
	</section>
	</dialog>`;

	const providerScript = editing
		? ""
		: `
			const outlookOAuthConfigured = ${outlookOAuthConfigured};
			const googleOAuthConfigured = ${googleOAuthConfigured};
			const presets = {
				gmail: { imapHost: "imap.gmail.com", imapPort: "993", smtpHost: "smtp.gmail.com", smtpPort: "465", smtpSecure: true, smtpEnabled: true, auth: "password" },
				icloud: { imapHost: "imap.mail.me.com", imapPort: "993", smtpHost: "smtp.mail.me.com", smtpPort: "587", smtpSecure: false, smtpEnabled: true, auth: "password" },
				outlook: { imapHost: "outlook.office365.com", imapPort: "993", smtpHost: "smtp.office365.com", smtpPort: "587", smtpSecure: false, smtpEnabled: true, auth: "oauth2" },
				yahoo: { imapHost: "imap.mail.yahoo.com", imapPort: "993", smtpHost: "smtp.mail.yahoo.com", smtpPort: "465", smtpSecure: true, smtpEnabled: true, auth: "password" },
				aol: { imapHost: "imap.aol.com", imapPort: "993", smtpHost: "smtp.aol.com", smtpPort: "465", smtpSecure: true, smtpEnabled: true, auth: "password" },
				qq: { imapHost: "imap.qq.com", imapPort: "993", smtpHost: "smtp.qq.com", smtpPort: "465", smtpSecure: true, smtpEnabled: true, auth: "password" },
				netease163: { imapHost: "imap.163.com", imapPort: "993", smtpHost: "smtp.163.com", smtpPort: "465", smtpSecure: true, smtpEnabled: true, auth: "password" },
				netease126: { imapHost: "imap.126.com", imapPort: "993", smtpHost: "smtp.126.com", smtpPort: "465", smtpSecure: true, smtpEnabled: true, auth: "password" },
				exmail: { imapHost: "imap.exmail.qq.com", imapPort: "993", smtpHost: "smtp.exmail.qq.com", smtpPort: "465", smtpSecure: true, smtpEnabled: true, auth: "password" },
				fastmail: { imapHost: "imap.fastmail.com", imapPort: "993", smtpHost: "smtp.fastmail.com", smtpPort: "465", smtpSecure: true, smtpEnabled: true, auth: "password" },
				zoho: { imapHost: "imap.zoho.com", imapPort: "993", smtpHost: "smtp.zoho.com", smtpPort: "465", smtpSecure: true, smtpEnabled: true, auth: "password" }
			};
			const byId = (id) => document.getElementById(id);
			function updateAuth() {
				const oauth = byId("auth-type").value === "oauth2";
				byId("password-field").hidden = oauth;
				byId("oauth-fields").hidden = !oauth;
				byId("password").required = !oauth;
				byId("access-token").required = oauth;
			}
			function updateProvider(provider) {
				const outlook = provider === "outlook";
				const google = provider === "gmail" && googleOAuthConfigured;
				const oauthSignIn = outlook || google;
				const form = byId("account-form");
				byId("account-detail-fields").hidden = false;
				const manualFields = byId("manual-account-fields");
				const submit = byId("account-submit");
				manualFields.hidden = oauthSignIn;
				form.action = outlook ? "/oauth/outlook/start" : google ? "/oauth/google/start" : "/accounts";
				submit.textContent = outlook ? "Continue with Microsoft" : google ? "Continue with Google" : "Test and save account";
				submit.disabled = outlook && !outlookOAuthConfigured;
				byId("account-help").textContent = outlook
					? outlookOAuthConfigured
						? "Sign in with Microsoft to authorize IMAP and SMTP access. Tokens are stored encrypted and are not shown in the browser."
						: "Set OUTLOOK_CLIENT_ID and OUTLOOK_CLIENT_SECRET to enable Microsoft sign-in."
					: google
						? "Sign in with Google to authorize IMAP and SMTP access. Tokens are stored encrypted and are not shown in the browser."
						: "Most providers require an app password or authorization code from the provider's security settings, not your normal sign-in password. Passwords and tokens are never displayed after saving.";
				const preset = presets[provider];
				byId("auth-type-field").hidden = Boolean(preset);
				if (preset) {
					byId("imap-host").value = preset.imapHost; byId("imap-port").value = preset.imapPort;
					byId("smtp-host").value = preset.smtpHost; byId("smtp-port").value = preset.smtpPort;
					byId("imap-secure").checked = true; byId("smtp-secure").checked = preset.smtpSecure;
					byId("smtp-enabled").checked = preset.smtpEnabled;
					byId("auth-type").value = preset.auth;
				} else {
					byId("imap-host").value = ""; byId("imap-port").value = "";
					byId("smtp-host").value = ""; byId("smtp-port").value = "";
					byId("imap-secure").checked = true; byId("smtp-secure").checked = false;
					byId("smtp-enabled").checked = false;
					byId("auth-type").value = "password";
				}
				manualFields.querySelectorAll("input, select, button").forEach((control) => control.disabled = oauthSignIn);
				if (!oauthSignIn) updateSmtp();
				updateAuth();
			}
			document.querySelectorAll("[data-provider]").forEach((button) => {
				button.addEventListener("click", () => {
					document.querySelectorAll("[data-provider]").forEach((option) => option.setAttribute("aria-pressed", String(option === button)));
					updateProvider(button.dataset.provider);
				});
			});
			byId("auth-type").addEventListener("change", updateAuth);
			`;
	const script = `<script>
		const accountDialog = document.getElementById("account-editor");
		const addAccountButton = document.getElementById("add-account-button");
		const smtpEnabled = document.getElementById("smtp-enabled");
		const smtpFields = document.getElementById("smtp-fields");
		function updateSmtp() {
			smtpFields.hidden = !smtpEnabled.checked;
			smtpFields.querySelectorAll("input").forEach((input) => input.disabled = !smtpEnabled.checked);
		}
		smtpEnabled.addEventListener("change", updateSmtp);
		updateSmtp();
		const closeAccountDialog = () => ${editing ? 'window.location.assign("/")' : "accountDialog.close()"};
		addAccountButton.addEventListener("click", () => {
			if (!accountDialog.open) accountDialog.showModal();
		});
		accountDialog.querySelectorAll("[data-dialog-close]").forEach((button) => {
			button.addEventListener("click", closeAccountDialog);
		});
		accountDialog.addEventListener("click", (event) => {
			if (event.target === accountDialog) closeAccountDialog();
		});
		${providerScript}
		${autoOpen ? "accountDialog.showModal();" : ""}
	</script>`;
	return { html, script };
}

function outlookConfigured(env: MailEnv): boolean {
	return Boolean(env.OUTLOOK_CLIENT_ID && env.OUTLOOK_CLIENT_SECRET);
}

function outlookConfig(env: MailEnv): {
	clientId: string;
	clientSecret: string;
	tenant: string;
} {
	if (!env.OUTLOOK_CLIENT_ID || !env.OUTLOOK_CLIENT_SECRET)
		throw new Error("Outlook OAuth is not configured");
	if (!/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(env.OUTLOOK_CLIENT_ID))
		throw new Error("OUTLOOK_CLIENT_ID must be a Microsoft Entra application client ID");
	const tenant = env.OUTLOOK_TENANT || "consumers";
	if (
		!/^(?:common|organizations|consumers|[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12})$/i.test(
			tenant,
		)
	)
		throw new Error("OUTLOOK_TENANT must be common, organizations, consumers, or a tenant ID");
	return {
		clientId: env.OUTLOOK_CLIENT_ID,
		clientSecret: env.OUTLOOK_CLIENT_SECRET,
		tenant,
	};
}

function googleConfigured(env: MailEnv): boolean {
	return Boolean(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET);
}

function googleConfig(env: MailEnv): {
	clientId: string;
	clientSecret: string;
} {
	if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET)
		throw new Error("Google OAuth is not configured");
	if (!/^[A-Za-z0-9_-]+\.apps\.googleusercontent\.com$/.test(env.GOOGLE_CLIENT_ID))
		throw new Error("GOOGLE_CLIENT_ID must be a Google OAuth client ID");
	return {
		clientId: env.GOOGLE_CLIENT_ID,
		clientSecret: env.GOOGLE_CLIENT_SECRET,
	};
}

function googleRedirectUri(request: Request): string {
	return `${new URL(request.url).origin}/oauth/google/callback`;
}

async function verifyGoogleIdentity(
	idToken: string,
	clientId: string,
	nonce: string,
): Promise<{ email: string }> {
	const { payload } = await jwtVerify(idToken, googleJwks, {
		issuer: ["https://accounts.google.com", "accounts.google.com"],
		audience: clientId,
	});
	if (payload.nonce !== nonce) throw new Error("Google identity token nonce is invalid");
	if (payload.email_verified !== true)
		throw new Error("Google identity token email is not verified");
	const email = typeof payload.email === "string" ? payload.email : undefined;
	if (!email) throw new Error("Google identity did not return an email address");
	return { email: validEmail(email) };
}

function outlookRedirectUri(request: Request): string {
	return `${new URL(request.url).origin}/oauth/outlook/callback`;
}

function oauthCookie(
	value: string,
	secure: boolean,
	name = "outlook_oauth",
	path = "/oauth/outlook/callback",
): string {
	return `${name}=${value}; Path=${path}; HttpOnly; SameSite=Lax; Max-Age=600${secure ? "; Secure" : ""}`;
}

function clearOauthCookie(
	secure: boolean,
	name = "outlook_oauth",
	path = "/oauth/outlook/callback",
): string {
	return `${name}=; Path=${path}; HttpOnly; SameSite=Lax; Max-Age=0${secure ? "; Secure" : ""}`;
}

function connectionTestCookie(secure: boolean, smtpConfigured: boolean): string {
	return `connection_test=${smtpConfigured ? "connection_ok" : "connection_imap_only"}; Path=/; HttpOnly; SameSite=Strict; Max-Age=60${secure ? "; Secure" : ""}`;
}

function clearConnectionTestCookie(secure: boolean): string {
	return `connection_test=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure ? "; Secure" : ""}`;
}

function cookieValue(request: Request, name: string): string | undefined {
	for (const part of (request.headers.get("Cookie") || "").split(";")) {
		const separator = part.indexOf("=");
		if (separator < 0 || part.slice(0, separator).trim() !== name) continue;
		return part.slice(separator + 1).trim() || undefined;
	}
	return undefined;
}

async function verifyMicrosoftIdentity(
	idToken: string,
	clientId: string,
	nonce: string,
): Promise<{ email: string }> {
	const unverified = decodeJwt(idToken);
	if (typeof unverified.tid !== "string" || !/^[0-9a-f-]{36}$/i.test(unverified.tid))
		throw new Error("Microsoft identity token has no valid tenant");
	const issuer = `https://login.microsoftonline.com/${unverified.tid}/v2.0`;
	const { payload } = await jwtVerify(idToken, microsoftJwks, {
		issuer,
		audience: clientId,
	});
	if (payload.nonce !== nonce) throw new Error("Microsoft identity token nonce is invalid");
	const email =
		typeof payload.preferred_username === "string"
			? payload.preferred_username
			: typeof payload.email === "string"
				? payload.email
				: undefined;
	if (!email) throw new Error("Microsoft identity did not return an email address");
	return { email: validEmail(email) };
}

function isTrustedFormSubmission(request: Request): boolean {
	if (request.headers.get("Sec-Fetch-Site") === "same-origin") return true;
	const origin = request.headers.get("Origin");
	if (origin === new URL(request.url).origin) return true;
	const referrer = request.headers.get("Referer");
	if (!referrer) return false;
	try {
		return new URL(referrer).origin === new URL(request.url).origin;
	} catch {
		return false;
	}
}

function accountInput(form: FormData, existingAuth?: AccountAuth): Omit<MailAccount, "id"> {
	let auth = existingAuth;
	if (!auth) {
		const authType = value(form, "authType");
		auth =
			authType === "password"
				? { type: "password", password: requiredSecret(form, "password") }
				: authType === "oauth2"
					? {
							type: "oauth2",
							accessToken: requiredSecret(form, "accessToken"),
							refreshToken: optionalSecret(form, "refreshToken"),
							clientId: optional(form, "oauthClientId"),
							tenant: optional(form, "oauthTenant") || "consumers",
						}
					: fail("Select a supported authentication type");
	}
	const email = validEmail(required(form, "email"));
	const settings = senderSettings({
		email,
		aliases: value(form, "aliases")
			.split(/[,;\n]+/)
			.map((alias) => alias.trim())
			.filter(Boolean),
		defaultFrom: optional(form, "defaultFrom"),
	});
	return {
		name: validName(required(form, "name")),
		email,
		...settings,
		imap: {
			host: validHost(required(form, "imapHost"), "IMAP host"),
			port: validPort(required(form, "imapPort"), "IMAP port"),
			secure: checkbox(form, "imapSecure"),
		},
		smtp: checkbox(form, "smtpEnabled")
			? {
					host: validHost(required(form, "smtpHost"), "SMTP host"),
					port: validPort(required(form, "smtpPort"), "SMTP port"),
					secure: checkbox(form, "smtpSecure"),
				}
			: undefined,
		auth,
	};
}

function value(form: FormData, name: string): string {
	const input = form.get(name);
	return typeof input === "string" ? input.trim() : "";
}

function required(form: FormData, name: string): string {
	const input = value(form, name);
	if (!input) throw new Error(`${name} is required`);
	return input;
}

function optional(form: FormData, name: string): string | undefined {
	return value(form, name) || undefined;
}

function requiredSecret(form: FormData, name: string): string {
	const input = form.get(name);
	if (typeof input !== "string" || !input) throw new Error(`${name} is required`);
	return input;
}

function optionalSecret(form: FormData, name: string): string | undefined {
	const input = form.get(name);
	return typeof input === "string" && input ? input : undefined;
}

function checkbox(form: FormData, name: string): boolean {
	return form.get(name) === "on";
}

function validPort(input: string, label: string): number {
	const port = Number(input);
	if (!Number.isInteger(port) || port < 1 || port > 65_535)
		throw new Error(`${label} must be between 1 and 65535`);
	return port;
}

function validEmail(input: string): string {
	if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input)) throw new Error("Enter a valid email address");
	return input;
}

function validName(input: string): string {
	if (input.length > 100) throw new Error("Display name must be 100 characters or fewer");
	return input;
}

function validHost(input: string, label: string): string {
	if (
		input.length > 253 ||
		!/^(?=.{1,253}$)(?:[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?\.)*[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?$/i.test(
			input,
		)
	)
		throw new Error(`${label} is invalid`);
	return input;
}

function fail(message: string): never {
	throw new Error(message);
}

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

function escapeHtml(value: string): string {
	return value.replace(
		/[&<>"']/g,
		(character) =>
			({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" })[character]!,
	);
}

export default app;
