import { Hono } from 'hono'
import { bodyLimit } from 'hono/body-limit'
import { timingSafeEqual } from 'hono/utils/buffer'
import * as jose from 'jose'

const app = new Hono()
const api = 'https://discord.com/api/v10'
const isSnowflake = value => typeof value === 'string' && /^\d{1,20}$/.test(value)

class OAuthError extends Error {
	constructor(code, status = 400) {
		super(code)
		this.status = status
	}
}

function config(env) {
	if (!isSnowflake(env.DISCORD_CLIENT_ID) || !env.DISCORD_CLIENT_SECRET ||
		!env.DISCORD_REDIRECT_URI || !env.OIDC_ISSUER) throw new Error('Missing configuration')
	const redirect = new URL(env.DISCORD_REDIRECT_URI)
	const issuer = new URL(env.OIDC_ISSUER)
	if (redirect.protocol !== 'https:' || issuer.protocol !== 'https:' ||
		redirect.username || redirect.password || issuer.username || issuer.password ||
		redirect.hash || issuer.hash || issuer.search) throw new Error('Invalid configuration')
	return {
		clientId: env.DISCORD_CLIENT_ID,
		clientSecret: env.DISCORD_CLIENT_SECRET,
		redirectURL: env.DISCORD_REDIRECT_URI,
		issuer: env.OIDC_ISSUER,
		serversToCheckRolesFor: JSON.parse(env.SERVERS_TO_CHECK_ROLES_FOR ?? '[]'),
	}
}

// Provision keys once before deployment. Request-time key generation races
// across Workers isolates because KV is eventually consistent.
async function loadKeys(KV) {
	const keys = await KV.get('keys', { type: 'json' })
	if (!keys?.privateKey || !keys?.publicKey || keys.publicKey.d) throw new Error('Missing keys')
	return keys
}

async function discordJSON(path, init = {}) {
	const response = await fetch(`${api}${path}`, { ...init, signal: AbortSignal.timeout(10000) })
	if (!response.ok) {
		if (path === '/oauth2/token' && response.status === 400) throw new OAuthError('invalid_grant')
		throw new OAuthError('temporarily_unavailable', 502)
	}
	return response.json()
}

async function authenticate(request, body, settings) {
	let clientId = body.get('client_id')
	let secret = body.get('client_secret')
	const authorization = request.header('Authorization')
	if (authorization) {
		if (clientId !== null || secret !== null || !/^Basic /i.test(authorization)) {
			throw new OAuthError('invalid_client', 401)
		}
		try {
			const decoded = atob(authorization.slice(6))
			const separator = decoded.indexOf(':')
			if (separator < 0) throw new Error('Invalid Basic credentials')
			clientId = decodeURIComponent(decoded.slice(0, separator).replace(/\+/g, ' '))
			secret = decodeURIComponent(decoded.slice(separator + 1).replace(/\+/g, ' '))
		} catch {
			throw new OAuthError('invalid_client', 401)
		}
	}
	if (clientId !== settings.clientId || typeof secret !== 'string' ||
		!await timingSafeEqual(secret, settings.clientSecret)) throw new OAuthError('invalid_client', 401)
}

app.use('*', async (c, next) => {
	c.header('Cache-Control', 'no-store')
	c.header('Pragma', 'no-cache')
	await next()
})
app.use('/token', bodyLimit({ maxSize: 16384, onError: c => c.json({ error: 'invalid_request' }, 413) }))
app.onError((error, c) => {
	// Never echo Discord responses, authorization codes, credentials or tokens.
	const status = error instanceof OAuthError ? error.status : 502
	if (status === 401) c.header('WWW-Authenticate', 'Basic realm="token"')
	return c.json({ error: error instanceof OAuthError ? error.message : 'temporarily_unavailable' }, status)
})

app.get('/authorize/:scopemode', async c => {
	const settings = config(c.env)
	const query = new URL(c.req.url).searchParams
	if ([...query.keys()].some(key => query.getAll(key).length !== 1) ||
		query.get('client_id') !== settings.clientId || query.get('redirect_uri') !== settings.redirectURL ||
		query.get('response_type') !== 'code' || !query.get('state') ||
		!['guilds', 'email'].includes(c.req.param('scopemode')) || query.has('nonce')) {
		throw new OAuthError('invalid_request')
	}
	const params = new URLSearchParams({
		client_id: settings.clientId,
		redirect_uri: settings.redirectURL,
		response_type: 'code',
		scope: c.req.param('scopemode') === 'guilds' ? 'identify email guilds' : 'identify email',
		state: query.get('state'),
	})
	if (query.has('code_challenge') || query.has('code_challenge_method')) {
		if (query.get('code_challenge_method') !== 'S256' || !/^[A-Za-z0-9_-]{43}$/.test(query.get('code_challenge') ?? '')) {
			throw new OAuthError('invalid_request')
		}
		params.set('code_challenge', query.get('code_challenge'))
		params.set('code_challenge_method', 'S256')
	}
	return c.redirect(`https://discord.com/oauth2/authorize?${params}`)
})

app.post('/token', async c => {
	const settings = config(c.env)
	if (c.req.header('Content-Type')?.split(';')[0].trim().toLowerCase() !== 'application/x-www-form-urlencoded') {
		throw new OAuthError('invalid_request')
	}
	const body = new URLSearchParams(await c.req.text())
	if ([...body.keys()].some(key => body.getAll(key).length !== 1)) throw new OAuthError('invalid_request')
	await authenticate(c.req, body, settings)
	if (body.get('grant_type') !== 'authorization_code') throw new OAuthError('unsupported_grant_type')
	if (!body.get('code') || body.get('redirect_uri') !== settings.redirectURL) throw new OAuthError('invalid_request')
	const params = new URLSearchParams({
		client_id: settings.clientId,
		client_secret: settings.clientSecret,
		redirect_uri: settings.redirectURL,
		code: body.get('code'),
		grant_type: 'authorization_code',
	})
	if (body.has('code_verifier')) {
		if (!/^[A-Za-z0-9._~-]{43,128}$/.test(body.get('code_verifier'))) throw new OAuthError('invalid_request')
		params.set('code_verifier', body.get('code_verifier'))
	}
	const keys = await loadKeys(c.env.KV)
	const token = await discordJSON('/oauth2/token', {
		method: 'POST', body: params, headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
	})
	if (typeof token.access_token !== 'string' || !token.access_token || typeof token.scope !== 'string' ||
		token.token_type?.toLowerCase() !== 'bearer') throw new OAuthError('temporarily_unavailable', 502)
	const scopes = new Set(token.scope.split(' '))
	if (!scopes.has('identify') || !scopes.has('email')) throw new OAuthError('invalid_scope')
	const headers = { Authorization: `Bearer ${token.access_token}` }
	const userInfo = await discordJSON('/users/@me', { headers })
	if (!isSnowflake(userInfo.id) || userInfo.verified !== true ||
		typeof userInfo.email !== 'string' || !userInfo.email || typeof userInfo.username !== 'string') {
		throw new OAuthError('access_denied', 403)
	}
	let servers = []
	if (scopes.has('guilds')) {
		let after = '0'
		// Never issue claims from a partial list or a failed Discord API request.
		for (let page = 0; ; page++) {
			if (page >= 10) throw new OAuthError('temporarily_unavailable', 502)
			const guilds = await discordJSON(`/users/@me/guilds?limit=200&after=${after}`, { headers })
			if (!Array.isArray(guilds) || guilds.some(guild => !isSnowflake(guild?.id))) {
				throw new OAuthError('temporarily_unavailable', 502)
			}
			servers.push(...guilds.map(guild => guild.id))
			if (guilds.length < 200) break
			const next = guilds[guilds.length - 1].id
			if (BigInt(next) <= BigInt(after)) throw new OAuthError('temporarily_unavailable', 502)
			after = next
		}
	}
	const roleClaims = {}
	if (!Array.isArray(settings.serversToCheckRolesFor) || settings.serversToCheckRolesFor.some(id => !isSnowflake(id))) {
		throw new Error('Invalid role configuration')
	}
	if (settings.serversToCheckRolesFor.length && !c.env.DISCORD_TOKEN) throw new Error('Missing bot token')
	for (const guildId of settings.serversToCheckRolesFor) {
		if (servers.includes(guildId)) {
			const member = await discordJSON(`/guilds/${guildId}/members/${userInfo.id}`, {
				headers: { Authorization: `Bot ${c.env.DISCORD_TOKEN}` },
			})
			if (!Array.isArray(member.roles) || member.roles.some(id => !isSnowflake(id))) {
				throw new OAuthError('temporarily_unavailable', 502)
			}
			roleClaims[`roles:${guildId}`] = member.roles
		}
	}
	const preferred_username = userInfo.discriminator && userInfo.discriminator !== '0'
		? `${userInfo.username}#${userInfo.discriminator}` : userInfo.username
	const idToken = await new jose.SignJWT({
		id: userInfo.id,
		preferred_username,
		email: userInfo.email,
		email_verified: true,
		name: userInfo.global_name ?? userInfo.username,
		guilds: [...new Set(servers)],
		...roleClaims,
	})
		.setProtectedHeader({ alg: 'RS256', kid: await jose.calculateJwkThumbprint(keys.publicKey) })
		.setIssuer(settings.issuer)
		.setSubject(userInfo.id)
		.setIssuedAt()
		.setExpirationTime('5m')
		.setAudience(settings.clientId)
		.sign(await jose.importJWK(keys.privateKey, 'RS256'))
	return c.json({ access_token: token.access_token, token_type: 'Bearer', expires_in: 300, scope: token.scope, id_token: idToken })
})

app.get('/jwks.json', async c => {
	const keys = await loadKeys(c.env.KV)
	// Export only a public CryptoKey, even if the KV entry is misconfigured.
	const publicKey = await jose.importJWK(keys.publicKey, 'RS256', { extractable: true })
	return c.json({ keys: [{ ...await jose.exportJWK(publicKey), alg: 'RS256', use: 'sig', kid: await jose.calculateJwkThumbprint(keys.publicKey) }] })
})

export default app
