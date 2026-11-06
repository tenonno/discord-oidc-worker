import { writeFile } from 'node:fs/promises'
import { generateKeyPair, exportJWK } from 'jose'

const pair = await generateKeyPair('RS256', { modulusLength: 2048, extractable: true })
const keys = { privateKey: await exportJWK(pair.privateKey), publicKey: await exportJWK(pair.publicKey) }
// Refuse to replace existing keys. Rotations require a separate rollout plan.
await writeFile('keys.local.json', JSON.stringify(keys), { flag: 'wx', mode: 0o600 })
console.log('Created keys.local.json. Treat it as a secret; provision it before deployment.')
