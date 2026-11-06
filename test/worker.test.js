import { test, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair, exportJWK, jwtVerify, createLocalJWKSet } from 'jose'
import app from '../worker.js'

const pair = await generateKeyPair('RS256', { extractable: true })
const keys = { privateKey: await exportJWK(pair.privateKey), publicKey: await exportJWK(pair.publicKey) }
const guildId = '1541821691125174334'
const env = {
	DISCORD_CLIENT_ID: '1568241417942466610',
	DISCORD_CLIENT_SECRET: 'test-only-secret',
	DISCORD_REDIRECT_URI: 'https://team.cloudflareaccess.com/cdn-cgi/access/callback',
	OIDC_ISSUER: 'https://oidc.example.com',
	KV: { get: async () => keys },
}
const originalFetch = globalThis.fetch
let calls
let guilds
let token
let user
let override
beforeEach(() => {
	calls = []
	guilds = [{ id: guildId }]
	token = { access_token: 'discord-test-token', token_type: 'Bearer', scope: 'identify email guilds', refresh_token: 'never-return-this' }
	user = { id: '123456789', verified: true, email: 'member@example.com', username: 'member', unexpected_private_field: 'omit-me' }
	override = undefined
	globalThis.fetch = async (url, init) => {
		calls.push({ url, init })
		const custom = await override?.(url, init)
		if (custom) return custom
		const path = new URL(url).pathname
		if (path === '/api/v10/oauth2/token') return Response.json(token)
		if (path === '/api/v10/users/@me') return Response.json(user)
		if (path === '/api/v10/users/@me/guilds') return Response.json(guilds)
		throw new Error('Unexpected test request')
	}
})
afterEach(() => { globalThis.fetch = originalFetch })

function authorize(changes = {}, path = 'guilds') {
	const query = new URLSearchParams({ client_id: env.DISCORD_CLIENT_ID, redirect_uri: env.DISCORD_REDIRECT_URI, response_type: 'code', state: 'session-state', ...changes })
	return app.request(`/authorize/${path}?${query}`, {}, env)
}
function exchange(changes = {}, options = {}) {
	const body = new URLSearchParams({ client_id: env.DISCORD_CLIENT_ID, client_secret: env.DISCORD_CLIENT_SECRET, code: 'single-use-code', grant_type: 'authorization_code', redirect_uri: env.DISCORD_REDIRECT_URI, ...changes })
	if (options.basic) {
		body.delete('client_id')
		body.delete('client_secret')
	}
	const headers = { 'Content-Type': 'application/x-www-form-urlencoded', ...options.headers }
	if (options.basic) headers.Authorization = `Basic ${btoa(`${env.DISCORD_CLIENT_ID}:${env.DISCORD_CLIENT_SECRET}`)}`
	return app.request('/token', { method: 'POST', headers, body: options.raw ?? body }, options.env ?? env)
}
async function verify(response) {
	assert.equal(response.status, 200)
	const body = await response.json()
	assert.equal(body.refresh_token, undefined)
	const jwks = await (await app.request('/jwks.json', {}, env)).json()
	assert.equal(jwks.keys[0].d, undefined)
	const verified = await jwtVerify(body.id_token, createLocalJWKSet(jwks), {
		issuer: env.OIDC_ISSUER, audience: env.DISCORD_CLIENT_ID, algorithms: ['RS256'],
	})
	assert.equal(verified.protectedHeader.kid, jwks.keys[0].kid)
	assert.equal(verified.payload.sub, user.id)
	assert.equal(verified.payload.exp - verified.payload.iat, 300)
	assert.equal(verified.payload.unexpected_private_field, undefined)
	return verified.payload
}

test('authorization preserves state and forwards S256 PKCE and guild scopes to Discord', async () => {
	const result = await authorize({ code_challenge: 'a'.repeat(43), code_challenge_method: 'S256' })
	assert.equal(result.status, 302)
	const url = new URL(result.headers.get('Location'))
	assert.equal(url.origin, 'https://discord.com')
	assert.equal(url.searchParams.get('state'), 'session-state')
	assert.equal(url.searchParams.get('redirect_uri'), env.DISCORD_REDIRECT_URI)
	assert.equal(url.searchParams.get('scope'), 'identify email guilds')
	assert.equal(url.searchParams.get('code_challenge'), 'a'.repeat(43))
	assert.equal(url.searchParams.get('code_challenge_method'), 'S256')
	assert.equal(url.searchParams.has('client_secret'), false)
})

for (const changes of [
	{ client_id: 'different-client' }, { redirect_uri: 'https://attacker.example.com/' },
	{ state: '' }, { response_type: 'token' }, { nonce: 'unsupported-nonce' },
	{ code_challenge: 'a'.repeat(43), code_challenge_method: 'plain' },
	{ code_challenge: 'short', code_challenge_method: 'S256' },
]) {
	test(`invalid authorization rejected: ${Object.keys(changes).join(',')}`, async () => {
		assert.equal((await authorize(changes)).status, 400)
		assert.equal(calls.length, 0)
	})
}

test('member receives signed guild ID claim through POST client authentication', async () => {
	const response = await exchange({ code_verifier: 'v'.repeat(43) })
	assert.equal(response.headers.get('Cache-Control'), 'no-store')
	assert.deepEqual((await verify(response)).guilds, [guildId])
	assert.equal(calls[0].init.body.get('code_verifier'), 'v'.repeat(43))
	assert.equal(calls[0].init.body.get('client_secret'), env.DISCORD_CLIENT_SECRET)
})

test('non-member has no target guild claim, including through Basic client authentication', async () => {
	guilds = [{ id: '999999999' }]
	const payload = await verify(await exchange({}, { basic: true }))
	assert.deepEqual(payload.guilds, ['999999999'])
	assert.equal(payload.guilds.includes(guildId), false)
})

test('no memberships returns an empty list', async () => {
	guilds = []
	assert.deepEqual((await verify(await exchange())).guilds, [])
})

test('email-only scope does not fetch guild membership', async () => {
	token.scope = 'identify email'
	assert.deepEqual((await verify(await exchange())).guilds, [])
	assert.equal(calls.length, 2)
})

test('paginated membership includes guilds on the next page', async () => {
	override = url => {
		if (url.includes('/users/@me/guilds?limit=200&after=0')) {
			return Response.json(Array.from({ length: 200 }, (_, i) => ({ id: String(i + 1) })))
		}
	}
	const payload = await verify(await exchange())
	assert.equal(payload.guilds.length, 201)
	assert.equal(payload.guilds.includes(guildId), true)
	assert.equal(calls.some(call => call.url.endsWith('after=200')), true)
})

for (const [changes, status] of [
	[{ client_secret: '' }, 401], [{ client_secret: 'wrong' }, 401], [{ client_id: 'wrong' }, 401],
	[{ grant_type: 'refresh_token' }, 400], [{ code: '' }, 400],
	[{ redirect_uri: 'https://attacker.example.com' }, 400], [{ code_verifier: 'short' }, 400],
]) {
	test(`token request rejected before contacting Discord: ${JSON.stringify(changes)}`, async () => {
		const response = await exchange(changes)
		assert.equal(response.status, status)
		assert.equal(calls.length, 0)
		assert.equal((await response.text()).includes(env.DISCORD_CLIENT_SECRET), false)
	})
}

test('conflicting authentication methods rejected', async () => {
	const response = await exchange({}, { headers: { Authorization: `Basic ${btoa('bad:credentials')}` } })
	assert.equal(response.status, 401)
	assert.equal(calls.length, 0)
})

test('duplicate form fields rejected', async () => {
	assert.equal((await exchange({}, { raw: 'code=a&code=b' })).status, 400)
	assert.equal(calls.length, 0)
})

test('JSON body and oversized requests rejected', async () => {
	assert.equal((await exchange({}, { headers: { 'Content-Type': 'application/json' }, raw: '{}' })).status, 400)
	assert.equal((await exchange({}, { raw: `code=${'a'.repeat(17000)}` })).status, 413)
	assert.equal(calls.length, 0)
})

test('unverified email is denied', async () => {
	user.verified = false
	assert.equal((await exchange()).status, 403)
})

test('rejected/replayed authorization code produces no token', async () => {
	override = url => url.endsWith('/oauth2/token') ? Response.json({ error: 'invalid_grant' }, { status: 400 }) : undefined
	const response = await exchange()
	assert.equal(response.status, 400)
	assert.deepEqual(await response.json(), { error: 'invalid_grant' })
	assert.equal(calls.length, 1)
})

for (const status of [401, 403, 429, 500]) {
	test(`guild API ${status} fails closed without a token or raw error details`, async () => {
		override = url => url.includes('/users/@me/guilds') ? Response.json({ secret: 'do-not-leak' }, { status }) : undefined
		const response = await exchange()
		assert.equal(response.status, 502)
		assert.deepEqual(await response.json(), { error: 'temporarily_unavailable' })
	})
}

test('malformed guild response fails closed', async () => {
	guilds = { message: 'not an array' }
	assert.equal((await exchange()).status, 502)
})

test('numeric guild IDs are rejected to avoid precision loss', async () => {
	guilds = [{ id: 1541821691125174334 }]
	assert.equal((await exchange()).status, 502)
})

test('network error fails closed', async () => {
	override = () => { throw new Error('sensitive-details') }
	const response = await exchange()
	assert.equal(response.status, 502)
	assert.deepEqual(await response.json(), { error: 'temporarily_unavailable' })
})

test('missing signing keys fails closed without generating or writing keys', async () => {
	const missing = { ...env, KV: { get: async () => null } }
	assert.equal((await exchange({}, { env: missing })).status, 502)
	assert.equal((await app.request('/jwks.json', {}, missing)).status, 502)
	assert.equal(calls.length, 0)
})

test('private material in public key is never exposed', async () => {
	const bad = { ...env, KV: { get: async () => ({ ...keys, publicKey: keys.privateKey }) } }
	const response = await app.request('/jwks.json', {}, bad)
	assert.equal(response.status, 502)
	assert.equal((await response.text()).includes(keys.privateKey.d), false)
})

test('optional role claims are returned only for a joined guild', async () => {
	const roleEnv = { ...env, SERVERS_TO_CHECK_ROLES_FOR: JSON.stringify([guildId, '999']), DISCORD_TOKEN: 'test-bot-token' }
	override = url => url.includes(`/guilds/${guildId}/members/`) ? Response.json({ roles: ['456'] }) : undefined
	const payload = await verify(await exchange({}, { env: roleEnv }))
	assert.deepEqual(payload[`roles:${guildId}`], ['456'])
	assert.equal(payload['roles:999'], undefined)
})
