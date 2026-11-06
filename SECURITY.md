# Security maintenance

This fork is maintained separately from [Erisa/discord-oidc-worker](https://github.com/Erisa/discord-oidc-worker).
Do not report vulnerabilities in a public issue or include credentials in reports.
Use GitHub private vulnerability reporting if it is enabled on the repository;
otherwise contact the repository owner privately before sharing details.

## Update policy

- Review weekly Dependabot pull requests for npm packages and GitHub Actions.
- Keep package-lock.json committed and install with npm ci.
- Require tests, bundle checks and npm audit before deploying. Do not auto-merge
  authentication changes or automatically deploy dependency updates.
- Track upstream changes with the upstream Git remote; review each before merging.
- An audit with zero findings is not a security audit of the authentication design.

## Scope and limitations

This is a Cloudflare Access adapter, not a general-purpose OIDC provider. Access
must check state on the direct Discord callback. Discord validates authorization
codes, their single-use property, redirect binding and any S256 PKCE verifier.
The adapter authenticates the token caller with client_secret_basic or
client_secret_post. Its credentials are the Discord application credentials.

Nonce-based OIDC flows are not supported: requests containing nonce are rejected,
not silently downgraded. Discovery, userinfo and refresh grants are not implemented.
These restrictions must be checked against the intended Access integration before
deployment. PKCE forwarding is tested with mocks; real Discord/Access acceptance
is a separate required check.

Guild membership is a snapshot at login. Leaving a server does not automatically
revoke an Access session. Configure session duration and revoke sessions when needed.
Do not leave an email-only, old account-member or bypass policy attached after the
guild-only migration is accepted.

Signing keys must be provisioned before deployment and backed up securely. Do not
overwrite existing keys casually; rotation requires a separate rollout procedure.
Disable request-body logging and avoid logging authorization URLs or token responses.
