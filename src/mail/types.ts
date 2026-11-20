export interface MailEnv extends Cloudflare.Env {}

export interface ServerConfig {
	host: string;
	port: number;
	secure: boolean;
}

export type AccountAuth =
	| { type: "password"; password: string }
	| {
			type: "oauth2";
			/** Defaults to "microsoft" for accounts saved before Google sign-in existed. */
			provider?: "microsoft" | "google";
			accessToken: string;
			refreshToken?: string;
			clientId?: string;
			tenant?: string;
			expiresAt?: number;
	  };

export interface MailAccount {
	id: string;
	name: string;
	email: string;
	/** Additional provider-authorized sending addresses; email remains the login username. */
	aliases?: string[];
	/** Defaults to email for accounts saved before sender settings were available. */
	defaultFrom?: string;
	imap: ServerConfig;
	smtp?: ServerConfig;
	auth: AccountAuth;
}
