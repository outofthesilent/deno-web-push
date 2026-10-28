// Web Push (RFC 8030 + VAPID RFC 8292 + Message Encryption RFC 8291) for Deno.
//
// Implemented natively against the Web Crypto API instead of pulling the npm
// `web-push` package because that package depends on Node's `crypto` module
// (not portable to Deno edge functions). This file is ~300 lines and handles:
//
//   - VAPID JWT signing (ES256 over ECDH P-256)
//   - aes128gcm message encryption per draft-ietf-webpush-encryption-08 / RFC 8291
//   - POST to the endpoint with the right headers
//   - 410 Gone surfaced so the caller can prune expired subscriptions
//
// Tested against FCM (Chrome/Android), Mozilla autopush (Firefox), and Apple's
// Web Push gateway (web.push.apple.com — iOS 16.4+ Safari home-screen apps).

export interface PushSubscription {
  endpoint: string;
  keys: { p256dh: string; auth: string };
}

export interface PushPayload {
  title: string;
  body: string;
  url?: string;
  icon?: string;
  badge?: string;
  tag?: string;
  data?: Record<string, unknown>;
}

export interface SendResult {
  ok: boolean;
  status: number;
  gone: boolean;          // 404 or 410 — subscription is dead, prune it
  error?: string;
}

// ---------- base64url helpers ----------
function b64urlEncode(buf: ArrayBuffer | Uint8Array): string {
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(s: string): Uint8Array {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

// ---------- VAPID key import ----------
async function importVapidPrivateKey(b64urlPrivate: string): Promise<CryptoKey> {
  // The VAPID private key as we generated it is a raw 32-byte scalar (P-256 d).
  // WebCrypto needs JWK (or pkcs8). Build JWK with the corresponding public
  // point so the key is usable for both sign + (the runtime needs the pub).
  const d = b64urlDecode(b64urlPrivate);
  // Derive the public point with the same ECDH machinery we used to mint.
  // Simpler: import as JWK and require the caller to also pass the pub.
  // To keep the API tight, we expect the caller to pass *both* the private and
  // public b64url keys, and we build the JWK here.
  throw new Error('use importVapidKeyPair instead');
}

async function importVapidKeyPair(
  pubB64url: string,
  privB64url: string,
): Promise<CryptoKey> {
  const pub = b64urlDecode(pubB64url);            // 65 bytes: 0x04 || X(32) || Y(32)
  const priv = b64urlDecode(privB64url);          // 32 bytes
  if (pub.length !== 65 || pub[0] !== 0x04) {
    throw new Error('VAPID public key must be uncompressed P-256 (65 bytes, 0x04 prefix)');
  }
  const x = pub.slice(1, 33);
  const y = pub.slice(33, 65);
  const jwk: JsonWebKey = {
    kty: 'EC',
    crv: 'P-256',
    x: b64urlEncode(x),
    y: b64urlEncode(y),
    d: b64urlEncode(priv),
    ext: true,
  };
  return await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign'],
  );
}

// ---------- VAPID JWT ----------
async function buildVapidJwt(
  audience: string,
  subject: string,
  vapidPubB64url: string,
  vapidPrivB64url: string,
): Promise<string> {
  const header = { typ: 'JWT', alg: 'ES256' };
  const now = Math.floor(Date.now() / 1000);
  const payload = { aud: audience, exp: now + 12 * 3600, sub: subject };
  const headerB64 = b64urlEncode(new TextEncoder().encode(JSON.stringify(header)));
  const payloadB64 = b64urlEncode(new TextEncoder().encode(JSON.stringify(payload)));
  const toSign = `${headerB64}.${payloadB64}`;
  const key = await importVapidKeyPair(vapidPubB64url, vapidPrivB64url);
  const sigDer = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    new TextEncoder().encode(toSign),
  );
  // WebCrypto returns raw r||s for ECDSA — exactly what JWS ES256 wants. Good.
  return `${toSign}.${b64urlEncode(sigDer)}`;
}

// ---------- HKDF + aes128gcm payload encryption (RFC 8291) ----------
async function hkdf(salt: Uint8Array, ikm: Uint8Array, info: Uint8Array, len: number): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    key,
    len * 8,
  );
  return new Uint8Array(bits);
}

function concat(...arrs: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrs) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

async function encryptPayloadAes128Gcm(
  plaintext: Uint8Array,
  clientPubKey: Uint8Array,      // 65 bytes uncompressed
  clientAuth: Uint8Array,        // 16 bytes
): Promise<{ body: Uint8Array; asPubKey: Uint8Array }> {
  // 1. Mint an ephemeral ECDH P-256 keypair (the "application server" key).
  const asKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'],
  );
  const asPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', asKeyPair.publicKey)); // 65 bytes

  // 2. Import client's public key for ECDH.
  const clientPubCrypto = await crypto.subtle.importKey(
    'raw', clientPubKey,
    { name: 'ECDH', namedCurve: 'P-256' },
    false, [],
  );
  const sharedSecret = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'ECDH', public: clientPubCrypto },
    asKeyPair.privateKey,
    256,
  ));

  // 3. salt (16 bytes random).
  const salt = crypto.getRandomValues(new Uint8Array(16));

  // 4. PRK_key = HKDF(auth, sharedSecret, "WebPush: info\0" || ua_public || as_public, 32)
  const keyInfo = concat(
    new TextEncoder().encode('WebPush: info\0'),
    clientPubKey,
    asPubRaw,
  );
  const ikm = await hkdf(clientAuth, sharedSecret, keyInfo, 32);

  // 5. CEK = HKDF(salt, IKM, "Content-Encoding: aes128gcm\0", 16)
  const cek = await hkdf(salt, ikm, new TextEncoder().encode('Content-Encoding: aes128gcm\0'), 16);

  // 6. NONCE = HKDF(salt, IKM, "Content-Encoding: nonce\0", 12)
  const nonce = await hkdf(salt, ikm, new TextEncoder().encode('Content-Encoding: nonce\0'), 12);

  // 7. Pad: plaintext || 0x02 (last record marker) — pad-len 0.
  const padded = concat(plaintext, new Uint8Array([0x02]));

  // 8. Encrypt.
  const cekKey = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    cekKey,
    padded,
  ));

  // 9. Build aes128gcm header per RFC 8188 §2.1:
  //    salt(16) || rs(4, big-endian) || idlen(1) || keyid(idlen) || ciphertext
  //    For Web Push, keyid is the application server public key (65 bytes).
  const rs = new Uint8Array(4);
  new DataView(rs.buffer).setUint32(0, 4096);
  const idlen = new Uint8Array([asPubRaw.length]);
  const body = concat(salt, rs, idlen, asPubRaw, ct);

  return { body, asPubKey: asPubRaw };
}

// ---------- public send fn ----------
export async function sendWebPush(
  subscription: PushSubscription,
  payload: PushPayload,
  vapid: { publicKey: string; privateKey: string; subject: string },
  ttlSeconds = 60,
): Promise<SendResult> {
  try {
    const endpoint = subscription.endpoint;
    const url = new URL(endpoint);
    const audience = `${url.protocol}//${url.host}`;

    const jwt = await buildVapidJwt(audience, vapid.subject, vapid.publicKey, vapid.privateKey);

    const clientPub = b64urlDecode(subscription.keys.p256dh);
    const clientAuth = b64urlDecode(subscription.keys.auth);
    const plaintext = new TextEncoder().encode(JSON.stringify(payload));

    const { body } = await encryptPayloadAes128Gcm(plaintext, clientPub, clientAuth);

    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Authorization': `vapid t=${jwt}, k=${vapid.publicKey}`,
        'Content-Encoding': 'aes128gcm',
        'Content-Type': 'application/octet-stream',
        'TTL': String(ttlSeconds),
        'Urgency': 'normal',
      },
      body,
    });

    return {
      ok: res.ok,
      status: res.status,
      gone: res.status === 404 || res.status === 410,
      error: res.ok ? undefined : `${res.status} ${res.statusText} — ${await res.text().catch(() => '')}`,
    };
  } catch (e) {
    return { ok: false, status: 0, gone: false, error: (e as Error).message };
  }
}
