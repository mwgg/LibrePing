// Browser-held identity. The user never sees a key — one is generated and kept
// in localStorage. The key IS the account: it signs subscriptions and alert
// rules so only the owner can change them, and its derived node ID is the
// owner handle the dashboard filters by.
//
// CRITICAL: the canonical encoders below must byte-match Go's protocol.canonical
// methods (pkg/protocol/owner.go). The Go test TestCrossLanguageVectors pins the
// signatures this code must reproduce from the same seed — keep them in sync.

import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import * as bip39 from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import sealedbox from "tweetnacl-sealedbox-js";

// @noble/ed25519 v2 needs a sync sha512 to offer synchronous sign/getPublicKey.
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const STORAGE_KEY = "libreping_seed_hex";

export interface Identity {
  seed: Uint8Array; // 32-byte Ed25519 seed
  pub: Uint8Array; // 32-byte public key
  owner: string; // node ID = hex(sha256(pub)[:8]) — matches Go identity.NodeIDFromPub
}

export function fromSeed(seed: Uint8Array): Identity {
  const pub = ed.getPublicKey(seed);
  // 16 bytes → 32 hex chars, matching Go identity.NodeIDFromPub (nodeIDBytes=16).
  const owner = bytesToHex(sha256(pub).slice(0, 16));
  return { seed, pub, owner };
}

// loadOrCreate returns the stored identity, creating and persisting one if none.
export function loadOrCreate(): Identity {
  let hex = localStorage.getItem(STORAGE_KEY);
  if (!hex) {
    const seed = ed.utils.randomPrivateKey(); // 32 bytes
    hex = bytesToHex(seed);
    localStorage.setItem(STORAGE_KEY, hex);
  }
  return fromSeed(hexToBytes(hex));
}

// recoveryPhrase exports the seed as a BIP39 mnemonic (24 words for 256 bits).
export function recoveryPhrase(id: Identity): string {
  return bip39.entropyToMnemonic(id.seed, wordlist);
}

// restoreFromPhrase imports a mnemonic, persists it, and returns the identity.
export function restoreFromPhrase(phrase: string): Identity {
  const seed = bip39.mnemonicToEntropy(phrase.trim(), wordlist);
  localStorage.setItem(STORAGE_KEY, bytesToHex(seed));
  return fromSeed(seed);
}

function b64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function fromB64(s: string): Uint8Array {
  const bin = atob(s);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

// --- Destination encryption (must mirror Go: hub/encbox + alert responsibility) ---

// HubKey identifies a hub we can seal a destination to.
export interface HubKey {
  hubId: string;
  encPubKey: string; // base64 X25519 public key
}

const ALERT_RECIPIENTS = 3; // top-K hubs that can decrypt (matches failover depth)

function sha256Hex(s: string, n: number): string {
  return bytesToHex(sha256(new TextEncoder().encode(s)).slice(0, n));
}

// alertDestHash is the stable, non-reversible fingerprint of a destination for
// an owner — matches Go protocol.AlertDestHash. Lets the dashboard correlate a
// locally-stored alert with the sealed rule the hub reports.
export function alertDestHash(owner: string, destination: string): string {
  return sha256Hex(owner + "|" + destination, 16);
}

// rendezvousScore mirrors Go hub/alert.score: big-endian uint64 of sha256(hubID|key)[:8].
function rendezvousScore(hubId: string, key: string): bigint {
  const h = sha256(new TextEncoder().encode(hubId + "|" + key));
  let v = 0n;
  for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(h[i]);
  return v;
}

// topKHubs picks the K highest-ranked hubs for a rule key (score desc, id desc),
// matching how Go chooses the responsible hub among recipients.
function topKHubs(hubs: HubKey[], key: string, k: number): HubKey[] {
  return [...hubs]
    .map((h) => ({ h, s: rendezvousScore(h.hubId, key) }))
    .sort((a, b) => (a.s < b.s ? 1 : a.s > b.s ? -1 : a.h.hubId < b.h.hubId ? 1 : -1))
    .slice(0, k)
    .map((x) => x.h);
}

function sealTo(encPubKeyB64: string, message: string): string {
  const sealed = sealedbox.seal(new TextEncoder().encode(message), fromB64(encPubKeyB64));
  return b64(sealed);
}

function signCanonical(id: Identity, canonical: string): { pubkey: string; signature: string } {
  const sig = ed.sign(new TextEncoder().encode(canonical), id.seed);
  return { pubkey: b64(id.pub), signature: b64(sig) };
}

export interface SubscriptionInput {
  checkId: string;
  intervalSeconds: number;
  expiryMs: number;
  updatedMs: number;
  deleted?: boolean;
}

// signSubscription builds the wire SignedSubscription the hub verifies. The
// canonical string MUST byte-match Go's Subscription.canonical (owner.go); the
// updated_ms version stamp lets the hub reject replays of older records.
export function signSubscription(id: Identity, s: SubscriptionInput) {
  const canonical = [
    "libreping-subscription-v2",
    id.owner,
    s.checkId,
    String(s.intervalSeconds),
    String(s.expiryMs),
    String(s.updatedMs),
    s.deleted ? "1" : "0",
  ].join("\n");
  const { pubkey, signature } = signCanonical(id, canonical);
  return {
    subscription: {
      owner: id.owner,
      check_id: s.checkId,
      interval_seconds: s.intervalSeconds,
      expiry_ms: s.expiryMs,
      updated_ms: s.updatedMs,
      ...(s.deleted ? { deleted: true } : {}),
    },
    pubkey,
    signature,
  };
}

// AlertChannel mirrors protocol.AlertChannel — every channel is a plain HTTPS
// POST to an owner-supplied destination (no hub config). `channel` is signed as a
// plain string in the canonical form, so this set can grow without a version bump.
export type AlertChannel = "webhook" | "ntfy" | "discord" | "slack";

export interface AlertInput {
  checkId: string;
  channel: AlertChannel;
  destination: string;
  failLocations: number;
  forSeconds: number;
  expiryMs: number;
  updatedMs: number;
  deleted?: boolean;
}

// signAlertRule builds the wire SignedAlertRule. The destination is never sent
// in the clear: it is sealed to the top-K rendezvous-responsible hubs (from
// `hubs`), so only those hubs can decrypt and notify.
export function signAlertRule(id: Identity, a: AlertInput, hubs: HubKey[]) {
  const destHash = sha256Hex(id.owner + "|" + a.destination, 16);
  const ruleKey = sha256Hex([id.owner, a.checkId, a.channel, destHash].join("|"), 8);

  const recipients: Record<string, string> = {};
  if (!a.deleted) {
    for (const h of topKHubs(hubs.filter((h) => h.encPubKey), ruleKey, ALERT_RECIPIENTS)) {
      recipients[h.hubId] = sealTo(h.encPubKey, a.destination);
    }
  }
  const recipientsCanonical = Object.keys(recipients)
    .sort()
    .map((k) => k + ":" + recipients[k])
    .join(",");

  const canonical = [
    "libreping-alert-v3",
    id.owner,
    a.checkId,
    a.channel,
    destHash,
    recipientsCanonical,
    String(a.failLocations),
    String(a.forSeconds),
    String(a.expiryMs),
    String(a.updatedMs),
    a.deleted ? "1" : "0",
  ].join("\n");
  const { pubkey, signature } = signCanonical(id, canonical);
  return {
    rule: {
      owner: id.owner,
      check_id: a.checkId,
      channel: a.channel,
      dest_hash: destHash,
      recipients,
      fail_locations: a.failLocations,
      for_seconds: a.forSeconds,
      expiry_ms: a.expiryMs,
      updated_ms: a.updatedMs,
      ...(a.deleted ? { deleted: true } : {}),
    },
    pubkey,
    signature,
  };
}
