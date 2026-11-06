# Discord OIDC adapter for Cloudflare Access

Maintenance fork of [Erisa/discord-oidc-worker](https://github.com/Erisa/discord-oidc-worker),
based on upstream commit `ba7b684`. The original MIT license and attribution remain.
The upstream project credits [kimcore/discord-oidc](https://github.com/kimcore/discord-oidc)
and [eidam/cf-access-workers-oidc](https://github.com/eidam/cf-access-workers-oidc).

This Worker lets Cloudflare Access receive Discord identity and guild IDs in a
signed token. Guild-only access needs neither a bot nor additional Discord roles.

**Migration status:** local tests and bundling are available. Real Discord/Access
login and rejection of a non-member must be verified before production cutover.
Read [SECURITY.md](SECURITY.md) for compatibility limits and maintenance duties.

## Differences from upstream

- Updated Hono, jose and Wrangler; lockfile and automated dependency update PRs.
- Client secret in Workers Secrets; no secret-bearing config.json bundled in code.
- Authenticate token callers (Basic or form credentials), validate redirects and
  grants, forward S256 PKCE and fail closed on Discord API errors.
- Provision signing keys once rather than generating conflicting keys on requests.
- Signed tokens contain an explicit identity claim allowlist, matching key ID,
  issuer, subject, issued-at and a five-minute expiry. No refresh token is returned.
- Guild-list pagination, regression tests and CI. No automatic deployment.

## Local checks

Use Node.js 22 or later (CI checks Node.js 22 and 24).

```sh
npm ci --ignore-scripts
npm test
npm run check
npm run build
npm audit
```

Build is a dry run and uses placeholder settings. It does not deploy a Worker.

## Deployment preparation

1. Create a Discord OAuth2 application, or use an existing dedicated one. Register
   `https://YOURTEAM.cloudflareaccess.com/cdn-cgi/access/callback` as a redirect.
   Unlike some other Discord proxies, the callback goes directly to Access.
2. Copy `wrangler.toml` to ignored `wrangler.local.toml`. Set a new Worker name,
   `DISCORD_CLIENT_ID`, `DISCORD_REDIRECT_URI`, and `OIDC_ISSUER` (the new Worker's
   HTTPS base URL, without a trailing slash). Leave role configuration `[]`.
3. Create a **new, dedicated** KV namespace and put its ID in wrangler.local.toml.
   Always specify --config to avoid accidentally using a parent project's settings.

```sh
npx wrangler kv namespace create KV --config wrangler.local.toml
```

4. Generate signing keys once. The script refuses to overwrite keys.local.json.
   This ignored file contains a private key. Store a secure backup, restrict local
   access, and never commit or paste its contents.

```sh
node scripts/generate-keys.mjs
npx wrangler kv key put keys --binding KV --path keys.local.json --remote --config wrangler.local.toml
```

Run this only for a new namespace; do not overwrite a deployed namespace's keys.
Wait for KV propagation before testing the deployment.

5. Set the Discord application's Client Secret through the interactive prompt:

```sh
npx wrangler secret put DISCORD_CLIENT_SECRET --config wrangler.local.toml
npx wrangler deploy --dry-run --config wrangler.local.toml
npx wrangler deploy --config wrangler.local.toml
```

Do not put the secret in configuration, shell arguments, GitHub issues or logs.
For local execution, use ignored .dev.vars and provision keys into local KV with
the same key-put command using --local instead of --remote.

## Cloudflare Access identity provider

Add a separate identity provider during migration so the existing one remains
available for rollback.

| Field | Value |
| --- | --- |
| Type | OpenID Connect |
| App ID | Discord application Client ID |
| Client secret | Discord application Client Secret |
| Auth URL | `https://NEW-WORKER.YOURNAME.workers.dev/authorize/guilds` |
| Token URL | `https://NEW-WORKER.YOURNAME.workers.dev/token` |
| Certificate URL | `https://NEW-WORKER.YOURNAME.workers.dev/jwks.json` |
| PKCE | Enabled, S256 (verify against the live integration) |
| OIDC Claims | `id`, `guilds` |
| OIDC scopes | Default `openid`, `email`, `profile` |

The /authorize/guilds path selects Discord's identify/email/guilds permissions.
`guilds` is a claim here, not an additional Access OIDC scope.
The prior proxy's generated OIDC client ID/secret are not used by this adapter.

Create an Allow policy with:

- Include: Login Methods = this new identity provider.
- Require: OIDC Claims, name `guilds`, value the allowed Discord server ID.

For Stephanos the value is `1541821691125174334`. The claim is an array of string
IDs; match the individual ID, not JSON array syntax.

Test the identity provider, then use a separate test Access application containing
only this policy. Test a member and a non-member with fresh sessions. Verify the
real portal only after these pass. The automated tests mock Discord and cannot
prove Access policy evaluation. Remove temporary email-based and old account-member
Allow policies after acceptance; otherwise those remain independent ways to enter.

If Access sends a nonce or omits required token fields, this adapter rejects the
request. Investigate the protocol mismatch before changing validation; do not
remove checks solely to make a login pass.

## Optional roles

Roles are not needed for guild membership. To use the upstream role feature, invite
the application's bot to the servers, set DISCORD_TOKEN as a Worker Secret, and set
SERVERS_TO_CHECK_ROLES_FOR to a JSON array of guild IDs in the local Wrangler vars.
Register `roles:GUILD_ID` as an Access claim and require the relevant role ID.

## Maintaining the fork

Keep origin pointed at tenonno/discord-oidc-worker and upstream at
Erisa/discord-oidc-worker. Review upstream changes and dependency PRs separately.
Dependabot and CI configuration must reach GitHub (Dependabot on the default branch)
before automation runs. Review and merge changes after checks; deployment is manual.

References: [Cloudflare custom claims](https://developers.cloudflare.com/cloudflare-one/integrations/identity-providers/generic-oidc/#custom-oidc-claims),
[Discord OAuth2](https://docs.discord.com/developers/topics/oauth2),
[Discord S256 metadata](https://discord.com/.well-known/oauth-authorization-server).
