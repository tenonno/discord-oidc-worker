import assert from 'node:assert/strict'
import { importJWK } from 'jose'

// Run against `wrangler dev --local` with the template settings and local keys.
// These requests never authenticate with or follow a redirect to Discord.
const base = 'http://127.0.0.1:8794'
const jwksResponse = await fetch(`${base}/jwks.json`)
assert.equal(jwksResponse.status, 200)
const jwks = await jwksResponse.json()
assert.equal(jwks.keys.length, 1)
assert.equal(jwks.keys[0].d, undefined)
assert.equal((await importJWK(jwks.keys[0], 'RS256')).type, 'public')

const params = new URLSearchParams({
  client_id: '000000000000000000',
  redirect_uri: 'https://YOURNAME.cloudflareaccess.com/cdn-cgi/access/callback',
  response_type: 'code', state: 'local-test',
  code_challenge: 'a'.repeat(43), code_challenge_method: 'S256',
})
const authorize = await fetch(`${base}/authorize/guilds?${params}`, { redirect: 'manual' })
assert.equal(authorize.status, 302)
const target = new URL(authorize.headers.get('Location'))
assert.equal(target.origin, 'https://discord.com')
assert.equal(target.searchParams.get('scope'), 'identify email guilds')
assert.equal(target.searchParams.get('code_challenge_method'), 'S256')

const denied = await fetch(`${base}/token`, {
  method: 'POST',
  body: new URLSearchParams({ client_id: '000000000000000000', client_secret: 'incorrect', code: 'invalid' }),
})
assert.equal(denied.status, 401)
assert.equal(denied.headers.get('Cache-Control'), 'no-store')
assert.deepEqual(await denied.json(), { error: 'invalid_client' })
console.log('Local Workers runtime: JWKS, authorization redirect and client rejection passed.')
