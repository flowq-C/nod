import { createHash } from 'node:crypto';
import { schnorr } from '@noble/curves/secp256k1.js';
import { z } from 'zod';
import { logRepeatedFailure } from '../../ports/failure-log.ts';
import type {
  InboundMessage,
  MessagingChannel,
  MessagingTransport,
} from '../../ports/messaging.ts';

type Environment = Record<string, string | undefined>;

const chatKind = 9;
const authKind = 22242;
const subscriptionId = 'nod-nostr-relay';
const identityPattern = /^[0-9a-f]{64}$/;
const signaturePattern = /^[0-9a-f]{128}$/;
const relayChannelPattern = /^[A-Za-z0-9_-]{1,64}$/;
const intakeLimit = 1000;
const lookbackSeconds = 30;
const publishTimeoutMs = 30_000;

const eventSchema = z.object({
  id: z.string().regex(identityPattern),
  pubkey: z.string().regex(identityPattern),
  created_at: z.number().int().nonnegative(),
  kind: z.number().int().nonnegative(),
  tags: z.array(z.array(z.string().max(2048)).max(32)).max(256),
  content: z.string().max(200_000),
  sig: z.string().regex(signaturePattern),
});

export type NostrRelayEvent = z.infer<typeof eventSchema>;

export type SocketFrame = { data?: unknown };
export interface RelaySocket {
  send(data: string): void;
  close(): void;
  addEventListener(
    type: 'open' | 'message' | 'close' | 'error',
    listener: (event: SocketFrame) => void,
  ): void;
}

const hexToBytes = (hex: string) => Uint8Array.from(Buffer.from(hex, 'hex'));
const bytesToHex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');

export function serializeEvent(event: Omit<NostrRelayEvent, 'id' | 'sig'>): string {
  return JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]);
}

export function signEvent(
  secretKey: string,
  input: { kind: number; tags: string[][]; content: string; created_at: number },
): NostrRelayEvent {
  const pubkey = bytesToHex(schnorr.getPublicKey(hexToBytes(secretKey)));
  const unsigned = { ...input, pubkey };
  const id = createHash('sha256').update(serializeEvent(unsigned)).digest('hex');
  const sig = bytesToHex(schnorr.sign(hexToBytes(id), hexToBytes(secretKey)));
  return { ...unsigned, id, sig };
}

export function verifyEvent(event: NostrRelayEvent): boolean {
  const { id, sig, ...unsigned } = event;
  if (createHash('sha256').update(serializeEvent(unsigned)).digest('hex') !== id) return false;
  return schnorr.verify(hexToBytes(sig), hexToBytes(id), hexToBytes(event.pubkey));
}

function list(value: string | undefined) {
  return (value ?? '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function socketUrl(value: string | undefined) {
  if (!value) return undefined;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return undefined;
  }
  const scheme =
    url.protocol === 'https:' ? 'wss:' : url.protocol === 'http:' ? 'ws:' : url.protocol;
  if (scheme !== 'ws:' && scheme !== 'wss:') return undefined;
  return `${scheme}//${url.host}${url.pathname === '/' ? '' : url.pathname}${url.search}`;
}

function replyTarget(event: NostrRelayEvent) {
  const replies = event.tags.filter((tag) => tag[0] === 'e' && identityPattern.test(tag[1] ?? ''));
  return (replies.find((tag) => tag[3] === 'reply') ?? replies.at(-1))?.[1];
}

function configuration(environment: Environment) {
  const env = { ...environment };
  const missing = [
    'NOSTR_RELAY_URL',
    'NOSTR_PRIVATE_KEY',
    'NOSTR_CHANNELS',
    'NOSTR_ALLOWED_PUBKEYS',
  ].filter((key) => !env[key]);
  const relayUrl = socketUrl(env.NOSTR_RELAY_URL);
  if (env.NOSTR_RELAY_URL && !relayUrl) missing.push('NOSTR_RELAY_URL');
  const secretKey = env.NOSTR_PRIVATE_KEY?.toLowerCase();
  if (secretKey && !identityPattern.test(secretKey)) missing.push('NOSTR_PRIVATE_KEY');
  const relayChannels = list(env.NOSTR_CHANNELS);
  if (
    env.NOSTR_CHANNELS &&
    (!relayChannels.length || relayChannels.some((id) => !relayChannelPattern.test(id)))
  )
    missing.push('NOSTR_CHANNELS');
  const allowedSenderIds = list(env.NOSTR_ALLOWED_PUBKEYS).map((key) => key.toLowerCase());
  if (
    env.NOSTR_ALLOWED_PUBKEYS &&
    (!allowedSenderIds.length || allowedSenderIds.some((key) => !identityPattern.test(key)))
  )
    missing.push('NOSTR_ALLOWED_PUBKEYS');
  const enabled = env.NOSTR_ENABLED === 'true';
  return {
    status: (!enabled
      ? 'disabled'
      : missing.length
        ? 'setup_required'
        : 'configured') as MessagingChannel['status'],
    missing: enabled ? missing : [],
    relayUrl,
    secretKey: secretKey && identityPattern.test(secretKey) ? secretKey : undefined,
    relayChannels,
    allowedSenderIds,
  };
}

export function createNostrRelayTransport(
  environment: Environment,
  options: { createSocket?: (url: string) => RelaySocket } = {},
): MessagingTransport {
  const config = configuration(environment);
  const accountId = config.secretKey
    ? bytesToHex(schnorr.getPublicKey(hexToBytes(config.secretKey)))
    : undefined;
  const channel: MessagingChannel = {
    id: 'nostr',
    status: config.status,
    missing: config.missing,
    ...(accountId ? { accountId } : {}),
    allowedSenderIds: [...config.allowedSenderIds],
  };
  const dropped = (reason: string) =>
    logRepeatedFailure('channel_inbound_dropped', `nostr:${reason}`, undefined, {
      provider: 'nostr',
      reason,
    });
  const incoming: InboundMessage[] = [];
  const pending = new Map<string, (accepted: boolean) => void>();
  let socket: RelaySocket | undefined;
  let authenticating = false;
  let attempt = 0;
  let reconnect: ReturnType<typeof setTimeout> | undefined;
  let closed = false;

  function intake(raw: unknown) {
    const parsed = eventSchema.safeParse(raw);
    if (!parsed.success) return dropped('invalid_event');
    const event = parsed.data;
    if (event.kind !== chatKind) return;
    if (!verifyEvent(event)) return dropped('invalid_signature');
    const sender = event.pubkey.toLowerCase();
    if (sender === accountId) return dropped('own_echo');
    const sentAt = event.created_at * 1000;
    if (!Number.isFinite(sentAt) || sentAt > Date.now() + 300_000) return dropped('invalid_time');
    const relayChannel = event.tags.find((tag) => tag[0] === 'h')?.[1];
    if (!relayChannel || !config.relayChannels.includes(relayChannel))
      return dropped('unsupported_channel');
    if (!event.tags.some((tag) => tag[0] === 'p' && tag[1]?.toLowerCase() === accountId))
      return dropped('not_addressed');
    if (!config.allowedSenderIds.includes(sender)) return dropped('sender_unmatched');
    const text = event.content.trim();
    if (!text) return dropped('unsupported_type');
    if (incoming.length >= intakeLimit) return dropped('queue_full');
    const reply = replyTarget(event);
    incoming.push({
      channelId: 'nostr',
      accountId: accountId!,
      senderId: sender,
      messageId: event.id,
      threadId: `${relayChannel}/${sender}`,
      text,
      sentAt: new Date(sentAt),
      ...(reply ? { replyToMessageId: reply } : {}),
    });
  }

  function sendFrame(current: RelaySocket, frame: unknown[]) {
    current.send(JSON.stringify(frame));
  }

  function subscribe(current: RelaySocket) {
    sendFrame(current, [
      'REQ',
      subscriptionId,
      {
        kinds: [chatKind],
        '#h': config.relayChannels,
        '#p': [accountId],
        since: Math.floor(Date.now() / 1000) - lookbackSeconds,
      },
    ]);
  }

  function authenticate(current: RelaySocket, challenge: unknown) {
    if (typeof challenge !== 'string' || !challenge || !config.secretKey || authenticating) return;
    authenticating = true;
    const event = signEvent(config.secretKey, {
      kind: authKind,
      tags: [
        ['challenge', challenge],
        ['relay', config.relayUrl!],
      ],
      content: '',
      created_at: Math.floor(Date.now() / 1000),
    });
    confirm(current, event, 'AUTH', () => {
      authenticating = false;
      // Always re-subscribe: the relay can close the pre-auth REQ after this answer.
      // A subscription sent before the authentication is no proof of a live one.
      subscribe(current);
    }).catch(() => {
      authenticating = false;
      disconnect(current, 'The Nostr relay authentication failed. Nod is trying to reconnect.');
    });
  }

  function frame(current: RelaySocket, data: unknown) {
    if (typeof data !== 'string') return;
    let message: unknown;
    try {
      message = JSON.parse(data);
    } catch {
      return;
    }
    if (!Array.isArray(message) || typeof message[0] !== 'string') return;
    const [type] = message;
    if (type === 'EVENT') return intake(message[2]);
    if (type === 'AUTH') return authenticate(current, message[1]);
    if (type === 'OK') {
      const id = typeof message[1] === 'string' ? message[1] : '';
      const finish = pending.get(id);
      if (finish) {
        pending.delete(id);
        finish(message[2] === true);
      }
      return;
    }
    if (type === 'CLOSED') {
      if (message[1] !== subscriptionId) return;
      // CLOSED leaves the connection up but silent, and receiving stops without error.
      // Rebuild the connection and the subscription instead.
      // Exception: an in-flight authentication answer re-subscribes on this connection.
      if (!authenticating)
        disconnect(current, 'The Nostr relay closed the subscription. Nod is trying to reconnect.');
    }
  }

  function confirm(
    current: RelaySocket,
    event: NostrRelayEvent,
    kind: 'EVENT' | 'AUTH',
    accepted?: () => void,
  ) {
    return new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(event.id);
        reject(new Error('Nostr relay delivery was not confirmed.'));
      }, publishTimeoutMs);
      timer.unref();
      pending.set(event.id, (ok) => {
        clearTimeout(timer);
        if (ok) {
          accepted?.();
          resolve(event.id);
        } else reject(new Error('Nostr relay delivery was not confirmed.'));
      });
      sendFrame(current, [kind, event]);
    });
  }

  async function send(
    current: RelaySocket,
    relayChannel: string,
    peer: string,
    replyToMessageId: string | undefined,
    text: string,
  ) {
    const event = signEvent(config.secretKey!, {
      kind: chatKind,
      tags: [
        ['h', relayChannel],
        ['p', peer],
        ...(replyToMessageId && identityPattern.test(replyToMessageId)
          ? [['e', replyToMessageId, '', 'reply']]
          : []),
      ],
      content: text,
      created_at: Math.floor(Date.now() / 1000),
    });
    return confirm(current, event, 'EVENT');
  }

  function disconnect(current: RelaySocket, message: string) {
    if (closed || socket !== current) return;
    socket = undefined;
    authenticating = false;
    channel.available = false;
    channel.error = message;
    for (const finish of pending.values()) finish(false);
    pending.clear();
    clearTimeout(reconnect);
    reconnect = setTimeout(connect, Math.min(60_000, 1000 * 2 ** Math.min(attempt++, 6)));
    reconnect.unref();
  }

  function connect() {
    if (closed || channel.status !== 'configured' || socket || !config.relayUrl) return;
    const current = (options.createSocket ?? ((url: string) => new WebSocket(url)))(
      config.relayUrl,
    );
    socket = current;
    authenticating = false;
    current.addEventListener('open', () => {
      if (closed || socket !== current) return;
      attempt = 0;
      channel.available = true;
      channel.error = undefined;
      subscribe(current);
    });
    current.addEventListener('message', (event) => {
      if (closed || socket !== current) return;
      frame(current, event.data);
    });
    current.addEventListener('close', () =>
      disconnect(current, 'The Nostr relay disconnected. Nod is trying to reconnect.'),
    );
    current.addEventListener('error', () =>
      disconnect(current, 'The Nostr relay connection failed. Nod is trying to reconnect.'),
    );
  }

  const thread = (value: string) => {
    const [relayChannel, peer, ...rest] = value.split('/');
    return rest.length ||
      !relayChannelPattern.test(relayChannel ?? '') ||
      !identityPattern.test(peer ?? '')
      ? undefined
      : { relayChannel: relayChannel!, peer: peer! };
  };
  function target(input: { channelId: string; accountId: string; threadId: string }) {
    const parsed = thread(input.threadId);
    if (
      input.channelId !== 'nostr' ||
      input.accountId !== channel.accountId ||
      !parsed ||
      !config.relayChannels.includes(parsed.relayChannel)
    )
      throw new Error('The Nostr relay target is unavailable.');
  }
  function connected() {
    if (!socket || !channel.available) throw new Error('The Nostr relay is disconnected.');
    return socket;
  }

  return {
    get channels() {
      return [channel];
    },
    async poll(accept) {
      if (closed || channel.status !== 'configured') return;
      if (!socket && !reconnect) connect();
      while (!closed && incoming.length) {
        await accept(incoming[0]);
        incoming.shift();
      }
    },
    async receive() {
      return { status: 404, body: { error: 'Nostr relay channels do not use a webhook.' } };
    },
    async post(input) {
      target(input);
      const current = connected();
      const { relayChannel, peer } = thread(input.threadId)!;
      const ids: string[] = [];
      if (input.text.trim())
        ids.push(await send(current, relayChannel, peer, input.replyToMessageId, input.text));
      const attachments = input.attachments ?? [];
      if (attachments.length) {
        const notice = await input
          .attachmentFailure?.(attachments.map((file) => file.name))
          .catch(() => undefined);
        if (notice?.trim())
          ids.push(await send(current, relayChannel, peer, input.replyToMessageId, notice));
      }
      if (!ids.length) throw new Error('Nostr relay delivery was not confirmed.');
      return { id: ids[0], ids };
    },
    async close() {
      if (closed) return;
      closed = true;
      clearTimeout(reconnect);
      for (const finish of pending.values()) finish(false);
      pending.clear();
      incoming.length = 0;
      const current = socket;
      socket = undefined;
      current?.close();
    },
  };
}
