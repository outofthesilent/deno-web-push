// Generate a VAPID keypair.
//
//   deno run keygen.ts
//
// Outputs base64url-encoded P-256 keys, the format every push service expects.
// Keep the private key secret; the public key is sent to browsers at subscribe
// time and travels in the Authorization header on every push.

function b64url(buf: ArrayBuffer | Uint8Array): string {
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (const b of u8) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const pair = await crypto.subtle.generateKey(
  { name: "ECDH", namedCurve: "P-256" },
  true,
  ["deriveBits"],
) as CryptoKeyPair;

const pub = await crypto.subtle.exportKey("raw", pair.publicKey);
const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);

console.log("VAPID_PUBLIC_KEY =", b64url(pub));
console.log("VAPID_PRIVATE_KEY =", jwk.d);
console.log();
console.log("Set these as environment variables. The subject you pass to");
console.log("sendWebPush must be a mailto: or https: URL.");
