// Minimal example: send one notification and prune the subscription if it is dead.
//
//   deno run --allow-net --allow-env example.ts
import { sendWebPush, type PushSubscription } from "./mod.ts";

const vapid = {
  publicKey: Deno.env.get("VAPID_PUBLIC_KEY")!,
  privateKey: Deno.env.get("VAPID_PRIVATE_KEY")!,
  subject: "mailto:you@example.com",
};

// In practice this comes from the browser's PushManager.subscribe() and is
// stored per user.
const subscription: PushSubscription = JSON.parse(
  Deno.env.get("TEST_SUBSCRIPTION")!,
);

const result = await sendWebPush(subscription, {
  title: "It works",
  body: "Sent from Deno with no dependencies.",
  url: "/",
}, vapid);

console.log(result);

if (result.gone) {
  console.log("Subscription is dead - remove it from storage.");
}
