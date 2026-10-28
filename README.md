# deno-web-push

Web Push for Deno, written against the Web Crypto API. No dependencies, no Node
shims, no build step.

```ts
import { sendWebPush } from "https://raw.githubusercontent.com/outofthesilent/deno-web-push/main/mod.ts";

const result = await sendWebPush(
  subscription,                       // { endpoint, keys: { p256dh, auth } }
  { title: "Lesson in 15 minutes", body: "Studio B with Ms. Rivera", url: "/today" },
  { publicKey: VAPID_PUBLIC, privateKey: VAPID_PRIVATE, subject: "mailto:you@example.com" },
);

if (result.gone) await removeSubscription(subscription.endpoint);
```

## Why this exists

The usual answer for sending browser push notifications from a server is the npm
`web-push` package. It depends on Node's `crypto` module, which means it does not
run on Deno — and therefore does not run on Supabase Edge Functions, Deno Deploy,
or anything else built on that runtime.

Push notifications are not a thing you can hand-wave. The payload must be
encrypted with `aes128gcm` per **RFC 8291**, and the request must be signed with
a VAPID JWT per **RFC 8292**. If either is wrong, the push service returns an
opaque error and the notification silently never arrives.

So this is that, implemented directly:

- **VAPID JWT signing** — ES256 over ECDH P-256
- **`aes128gcm` payload encryption** — HKDF key derivation per RFC 8291
- **Correct headers** — `Authorization: vapid`, `Content-Encoding`, `TTL`, `Urgency`
- **`410 Gone` surfaced** as `result.gone`, so dead subscriptions can be pruned
  instead of being retried forever

About 240 lines, standard library only.

## Tested against

- **FCM** — Chrome and Android
- **Mozilla autopush** — Firefox
- **Apple Web Push** — `web.push.apple.com`, iOS 16.4+ Safari home-screen apps

## Generating VAPID keys

```bash
deno run https://raw.githubusercontent.com/outofthesilent/deno-web-push/main/keygen.ts
```

Or any existing VAPID keypair works — the format is standard base64url.

## API

```ts
sendWebPush(
  subscription: PushSubscription,
  payload: PushPayload,
  vapid: { publicKey: string; privateKey: string; subject: string },
  ttlSeconds = 60,
): Promise<SendResult>
```

`SendResult` is `{ ok, status, gone, error? }`. Nothing throws on a failed push —
check `ok`, and check `gone` before retrying.

## Notes

The `subject` must be a `mailto:` or `https:` URL. Push services reject VAPID
JWTs without one, and the error they return does not say so.

Extracted from a production system that delivers lesson reminders and schedule
changes to parent and teacher PWAs.

## License

MIT
