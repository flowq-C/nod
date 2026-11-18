import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import test from 'node:test';
import { setTimeout as sleep } from 'node:timers/promises';
import { schnorr } from '@noble/curves/secp256k1.js';
import Fastify from 'fastify';
import pg from 'pg';
import { ChannelSetupFailure } from '../src/ports/channel-settings.ts';
import { MessagingNotSentError } from '../src/ports/messaging.ts';
import type { InboundMessage, MessagingTransport } from '../src/ports/messaging.ts';
import { combineMessagingTransports } from '../src/providers/chat-sdk/combined.ts';
import {
  createNostrRelayTransport,
  serializeEvent,
  signEvent,
  verifyEvent,
  type NostrRelayEvent,
  type RelaySocket,
  type SocketFrame,
} from '../src/providers/nostr-relay/index.ts';
import { createNostrRelaySetupVerifier } from '../src/providers/nostr-relay/settings.ts';
import {
  createChannelSettings,
  managedChannelEnvironment,
} from '../src/server/channel-settings.ts';

const bipSecret = `${'0'.repeat(62)}03`;
const bipPublic = 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9';
const bipMessage = '00'.repeat(32);
const bipAux = '00'.repeat(32);
const bipSignature =
  'e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0';

const botSecret = `01${'0'.repeat(62)}`;
const senderSecret = `02${'0'.repeat(62)}`;
const strangerSecret = `04${'0'.repeat(62)}`;

const hexToBytes = (hex: string) => Uint8Array.from(Buffer.from(hex, 'hex'));
const bytesToHex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');
const identity = (secret: string) => bytesToHex(schnorr.getPublicKey(hexToBytes(secret)));

const botIdentity = identity(botSecret);
const senderIdentity = identity(senderSecret);
const strangerIdentity = identity(strangerSecret);

const environment = () => ({
  NOSTR_ENABLED: 'true',
  NOSTR_RELAY_URL: 'https://relay.example',
  NOSTR_PRIVATE_KEY: botSecret,
  NOSTR_CHANNELS: 'room',
  NOSTR_ALLOWED_PUBKEYS: senderIdentity,
});

class FakeSocket implements RelaySocket {
  readyState = 0;
  closed = false;
  readonly sent: unknown[][] = [];
  private readonly listeners = new Map<string, ((event: SocketFrame) => void)[]>();

  addEventListener(type: string, listener: (event: SocketFrame) => void) {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]);
  }

  send(data: string) {
    this.sent.push(JSON.parse(data) as unknown[]);
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    this.readyState = 3;
    this.emit('close', {});
  }

  open() {
    this.readyState = 1;
    this.emit('open', {});
  }

  message(frame: unknown[]) {
    this.emit('message', { data: JSON.stringify(frame) });
  }

  frames(type: string) {
    return this.sent.filter((frame) => frame[0] === type);
  }

  private emit(type: string, event: SocketFrame) {
    for (const listener of this.listeners.get(type) ?? []) listener(event);
  }
}

function connectedTransport() {
  const socket = new FakeSocket();
  const transport = createNostrRelayTransport(environment(), { createSocket: () => socket });
  const received: InboundMessage[] = [];
  const collect = async (message: InboundMessage) => {
    received.push(message);
  };
  return { socket, transport, received, collect };
}

test('relay events carry a spec-canonical id and a BIP340 signature and reject tampering', () => {
  assert.equal(bytesToHex(schnorr.getPublicKey(hexToBytes(bipSecret))), bipPublic);
  assert.equal(
    bytesToHex(schnorr.sign(hexToBytes(bipMessage), hexToBytes(bipSecret), hexToBytes(bipAux))),
    bipSignature,
  );
  assert.ok(
    schnorr.verify(hexToBytes(bipSignature), hexToBytes(bipMessage), hexToBytes(bipPublic)),
  );

  const event = signEvent(senderSecret, {
    kind: 9,
    tags: [
      ['h', 'room'],
      ['p', botIdentity],
    ],
    content: 'hello',
    created_at: 1_700_000_000,
  });
  assert.equal(event.pubkey, senderIdentity);
  assert.equal(event.id, createHash('sha256').update(serializeEvent(event)).digest('hex'));
  assert.ok(verifyEvent(event));
  assert.equal(verifyEvent({ ...event, content: 'forged' }), false);
  assert.equal(verifyEvent({ ...event, pubkey: strangerIdentity }), false);
  assert.equal(verifyEvent({ ...event, sig: `00${event.sig.slice(2)}` }), false);
});

test('registers the nostr channel like the other chat channels', () => {
  const disabled = createNostrRelayTransport({}).channels[0];
  assert.equal(disabled.id, 'nostr');
  assert.equal(disabled.status, 'disabled');
  assert.deepEqual(disabled.missing, []);

  const incomplete = createNostrRelayTransport({ NOSTR_ENABLED: 'true' }).channels[0];
  assert.equal(incomplete.status, 'setup_required');
  assert.deepEqual([...incomplete.missing].sort(), [
    'NOSTR_ALLOWED_PUBKEYS',
    'NOSTR_PRIVATE_KEY',
    'NOSTR_RELAY_URL',
  ]);

  const invalid = createNostrRelayTransport({
    ...environment(),
    NOSTR_RELAY_URL: 'ftp://relay.example',
    NOSTR_PRIVATE_KEY: 'not-a-key',
    NOSTR_CHANNELS: '',
    NOSTR_ALLOWED_PUBKEYS: 'not-a-key',
  }).channels[0];
  assert.equal(invalid.status, 'setup_required');
  assert.deepEqual([...invalid.missing].sort(), [
    'NOSTR_ALLOWED_PUBKEYS',
    'NOSTR_PRIVATE_KEY',
    'NOSTR_RELAY_URL',
  ]);

  const configured = createNostrRelayTransport(environment()).channels[0];
  assert.equal(configured.status, 'configured');
  assert.equal(configured.accountId, botIdentity);
  assert.deepEqual(configured.allowedSenderIds, [senderIdentity]);
});

test('accepts addressed channel messages into their thread and drops the rest', async () => {
  const { socket, transport, received, collect } = connectedTransport();
  await transport.poll?.(collect);
  socket.open();

  const base = { kind: 9, created_at: Math.floor(Date.now() / 1000), content: 'hello' };
  const addressedEvent = signEvent(senderSecret, {
    ...base,
    tags: [
      ['h', 'room'],
      ['p', botIdentity],
      ['e', 'a'.repeat(64), '', 'reply'],
    ],
  });
  socket.message(['EVENT', 'sub', addressedEvent]);
  await transport.poll?.(collect);
  assert.equal(received.length, 1);
  const message = received[0];
  assert.equal(message.channelId, 'nostr');
  assert.equal(message.accountId, botIdentity);
  assert.equal(message.senderId, senderIdentity);
  assert.equal(message.messageId, addressedEvent.id);
  assert.equal(message.threadId, `room/${senderIdentity}`);
  assert.equal(message.text, 'hello');
  assert.equal(message.replyToMessageId, 'a'.repeat(64));
  assert.equal(message.sentAt.getTime(), base.created_at * 1000);

  socket.message([
    'EVENT',
    'sub',
    signEvent(botSecret, {
      ...base,
      tags: [
        ['h', 'room'],
        ['p', botIdentity],
      ],
    }),
  ]);
  socket.message([
    'EVENT',
    'sub',
    signEvent(senderSecret, {
      ...base,
      tags: [
        ['h', 'room'],
        ['p', strangerIdentity],
      ],
    }),
  ]);
  socket.message(['EVENT', 'sub', signEvent(senderSecret, { ...base, tags: [['h', 'room']] })]);
  socket.message([
    'EVENT',
    'sub',
    signEvent(strangerSecret, {
      ...base,
      tags: [
        ['h', 'room'],
        ['p', botIdentity],
      ],
    }),
  ]);
  const forged = signEvent(senderSecret, {
    ...base,
    tags: [
      ['h', 'room'],
      ['p', botIdentity],
    ],
  });
  socket.message(['EVENT', 'sub', { ...forged, content: 'forged' }]);
  socket.message([
    'EVENT',
    'sub',
    signEvent(senderSecret, {
      ...base,
      created_at: Math.floor(Date.now() / 1000) + 400,
      tags: [
        ['h', 'room'],
        ['p', botIdentity],
      ],
    }),
  ]);
  socket.message([
    'EVENT',
    'sub',
    signEvent(senderSecret, {
      ...base,
      tags: [
        ['h', 'other'],
        ['p', botIdentity],
      ],
    }),
  ]);
  await transport.poll?.(collect);
  assert.equal(received.length, 2);
});

test('answers NIP-42 authentication and restores the subscription', async () => {
  const { socket, transport, collect } = connectedTransport();
  await transport.poll?.(collect);
  socket.open();

  const chatRequests = () => socket.frames('REQ').filter((frame) => frame[1] === 'nod-nostr-relay');
  const first = chatRequests();
  assert.equal(first.length, 1);
  assert.deepEqual(first[0][1], 'nod-nostr-relay');
  const filter = first[0][2] as Record<string, unknown>;
  assert.deepEqual(filter.kinds, [9]);
  assert.deepEqual(filter['#h'], ['room']);
  assert.equal(filter['#p'], undefined);

  socket.message(['AUTH', 'challenge-1']);
  const auth = socket.frames('AUTH')[0][1] as NostrRelayEvent;
  assert.equal(auth.kind, 22242);
  assert.equal(auth.content, '');
  assert.deepEqual(auth.tags, [
    ['challenge', 'challenge-1'],
    ['relay', 'wss://relay.example'],
  ]);
  assert.ok(verifyEvent(auth));
  socket.message(['OK', auth.id, true, '']);
  assert.equal(chatRequests().length, 2);

  socket.message(['AUTH', 'challenge-2']);
  const again = socket.frames('AUTH')[1][1] as NostrRelayEvent;
  assert.deepEqual(again.tags, [
    ['challenge', 'challenge-2'],
    ['relay', 'wss://relay.example'],
  ]);
  socket.message(['CLOSED', 'nod-nostr-relay', 'auth-required: restricted']);
  assert.equal(transport.channels[0].available, true);
  socket.message(['OK', again.id, true, '']);
  assert.equal(chatRequests().length, 3);

  socket.message(['CLOSED', 'nod-nostr-relay', 'rate limited']);
  assert.equal(transport.channels[0].available, false);
  assert.match(transport.channels[0].error ?? '', /closed the subscription/);
});

test('rebuilds the connection and the subscription after the relay closes it', async () => {
  const sockets: FakeSocket[] = [];
  const transport = createNostrRelayTransport(environment(), {
    createSocket: () => {
      const socket = new FakeSocket();
      sockets.push(socket);
      return socket;
    },
  });
  const collect = async (_message: InboundMessage) => {};
  await transport.poll?.(collect);
  const chatRequests = (socket: FakeSocket) =>
    socket.frames('REQ').filter((frame) => frame[1] === 'nod-nostr-relay');
  sockets[0].open();
  assert.equal(chatRequests(sockets[0]).length, 1);

  sockets[0].message(['CLOSED', 'nod-nostr-relay', 'rate limited']);
  await sleep(1200);
  await transport.poll?.(collect);
  assert.equal(sockets.length, 2);
  sockets[1].open();
  assert.equal(chatRequests(sockets[1]).length, 1);
});

test('keeps at most one relay connection open across repeated failures', async () => {
  const sockets: FakeSocket[] = [];
  const transport = createNostrRelayTransport(environment(), {
    createSocket: () => {
      const socket = new FakeSocket();
      sockets.push(socket);
      return socket;
    },
  });
  const collect = async (_message: InboundMessage) => {};
  await transport.poll?.(collect);
  sockets[0].open();
  sockets[0].message(['CLOSED', 'nod-nostr-relay', 'rate limited']);
  await sleep(1200);
  await transport.poll?.(collect);
  sockets[1].open();
  sockets[1].message(['AUTH', 'challenge']);
  const auth = sockets[1].frames('AUTH')[0][1] as NostrRelayEvent;
  sockets[1].message(['OK', auth.id, false, 'denied']);
  await sleep(2200);
  await transport.poll?.(collect);
  sockets[2].open();
  sockets[2].message(['CLOSED', 'nod-nostr-relay', 'rate limited']);
  await sleep(4200);
  await transport.poll?.(collect);
  sockets[3].open();

  assert.equal(sockets.filter((socket) => !socket.closed).length, 1);
  await transport.close!();
  assert.ok(sockets.every((socket) => socket.closed));
});

test('keeps chat events with protocol tag shapes', async () => {
  const { socket, transport, received, collect } = connectedTransport();
  await transport.poll?.(collect);
  socket.open();
  const mentions = Array.from({ length: 12 }, (_, index) => [
    'p',
    `${index}`.padStart(64, '0'),
    'wss://relay.example',
    `Member ${index}`,
  ]);
  const event = signEvent(senderSecret, {
    kind: 9,
    created_at: Math.floor(Date.now() / 1000),
    tags: [
      ['h', 'room'],
      ['p', botIdentity],
      ['e', 'a'.repeat(64), 'wss://relay.example', 'reply'],
      ...mentions,
    ],
    content: 'many mentions',
  });
  socket.message(['EVENT', 'sub', event]);
  await transport.poll?.(collect);
  assert.equal(received.length, 1);
  assert.equal(received[0].replyToMessageId, 'a'.repeat(64));
});

test('gives separate sends separate event ids and keeps the id on a retry', async () => {
  const { socket, transport, collect } = connectedTransport();
  await transport.poll?.(collect);
  socket.open();

  const post = () =>
    transport.post({
      channelId: 'nostr',
      accountId: botIdentity,
      threadId: `room/${senderIdentity}`,
      text: 'same',
    });
  const first = post();
  const second = post();
  const events = socket.frames('EVENT');
  assert.equal(events.length, 2);
  const firstEvent = events[0][1] as NostrRelayEvent;
  const secondEvent = events[1][1] as NostrRelayEvent;
  assert.notEqual(firstEvent.id, secondEvent.id);
  assert.notEqual(firstEvent.tags.at(-1)?.[1], secondEvent.tags.at(-1)?.[1]);
  socket.message(['OK', firstEvent.id, true, '']);
  socket.message(['OK', secondEvent.id, true, '']);
  assert.deepEqual(await first, { id: firstEvent.id, ids: [firstEvent.id] });
  assert.deepEqual(await second, { id: secondEvent.id, ids: [secondEvent.id] });

  const failed = transport.post({
    channelId: 'nostr',
    accountId: botIdentity,
    threadId: `room/${senderIdentity}`,
    text: 'retry me',
  });
  const attempt = socket.frames('EVENT')[2][1] as NostrRelayEvent;
  socket.message(['OK', attempt.id, false, 'blocked']);
  await assert.rejects(failed, /Nostr relay delivery was not confirmed/);

  const retry = transport.post({
    channelId: 'nostr',
    accountId: botIdentity,
    threadId: `room/${senderIdentity}`,
    text: 'retry me',
  });
  const replay = socket.frames('EVENT')[3][1] as NostrRelayEvent;
  assert.equal(replay.id, attempt.id);
  socket.message(['OK', replay.id, true, '']);
  assert.deepEqual(await retry, { id: attempt.id, ids: [attempt.id] });
});

test('posts kind 9 replies only after relay confirmation', async () => {
  const { socket, transport, collect } = connectedTransport();
  await transport.poll?.(collect);
  socket.open();

  const reply = transport.post({
    channelId: 'nostr',
    accountId: botIdentity,
    threadId: `room/${senderIdentity}`,
    text: 'done',
    replyToMessageId: 'b'.repeat(64),
  });
  const sent = socket.frames('EVENT')[0][1] as NostrRelayEvent;
  assert.equal(sent.kind, 9);
  assert.deepEqual(sent.tags.slice(0, 3), [
    ['h', 'room'],
    ['p', senderIdentity],
    ['e', 'b'.repeat(64), '', 'reply'],
  ]);
  assert.equal(sent.tags.length, 4);
  assert.equal(sent.tags[3][0], 'nonce');
  assert.match(sent.tags[3][1], /^[0-9a-f]{32}$/);
  assert.equal(sent.content, 'done');
  assert.ok(verifyEvent(sent));
  socket.message(['OK', sent.id, true, '']);
  assert.deepEqual(await reply, { id: sent.id, ids: [sent.id] });

  const rejected = transport.post({
    channelId: 'nostr',
    accountId: botIdentity,
    threadId: `room/${senderIdentity}`,
    text: 'again',
  });
  const refused = socket.frames('EVENT')[1][1] as NostrRelayEvent;
  socket.message(['OK', refused.id, false, 'blocked']);
  await assert.rejects(rejected, /Nostr relay delivery was not confirmed/);

  const notice = transport.post({
    channelId: 'nostr',
    accountId: botIdentity,
    threadId: `room/${senderIdentity}`,
    text: '',
    attachments: [
      {
        name: 'report.pdf',
        mimeType: 'application/pdf',
        size: 3,
        async read() {
          return new Uint8Array([1, 2, 3]);
        },
      },
    ],
    attachmentFailure: async (names) => `Files stay in the app: ${names.join(', ')}`,
  });
  await sleep(0);
  assert.equal(socket.frames('EVENT').length, 3);
  const noticeEvent = socket.frames('EVENT')[2][1] as NostrRelayEvent;
  assert.equal(noticeEvent.content, 'Files stay in the app: report.pdf');
  socket.message(['OK', noticeEvent.id, true, '']);
  assert.deepEqual(await notice, { id: noticeEvent.id, ids: [noticeEvent.id] });

  await assert.rejects(
    transport.post({
      channelId: 'nostr',
      accountId: botIdentity,
      threadId: `room/${senderIdentity}`,
      text: '',
      attachments: [
        {
          name: 'report.pdf',
          mimeType: 'application/pdf',
          size: 3,
          async read() {
            return new Uint8Array([1, 2, 3]);
          },
        },
      ],
    }),
    /Nostr relay delivery was not confirmed/,
  );

  await assert.rejects(
    transport.post({
      channelId: 'telegram',
      accountId: botIdentity,
      threadId: `room/${senderIdentity}`,
      text: 'wrong channel',
    }),
    /The Nostr relay target is unavailable/,
  );
  await assert.rejects(
    transport.post({
      channelId: 'nostr',
      accountId: botIdentity,
      threadId: 'room',
      text: 'wrong thread',
    }),
    (error: Error) =>
      /The Nostr relay target is unavailable/.test(error.message) &&
      !(error instanceof MessagingNotSentError),
  );

  const webhook = await transport.receive({
    channelId: 'nostr',
    method: 'POST',
    headers: {},
    query: {},
    body: new Uint8Array(),
  });
  assert.equal(webhook.status, 404);
});

test('does not connect while the channel is not configured', async () => {
  const socket = new FakeSocket();
  const transport = createNostrRelayTransport({}, { createSocket: () => socket });
  await transport.poll?.(async () => {});
  assert.equal(socket.frames('REQ').length, 0);
  await assert.rejects(
    transport.post({
      channelId: 'nostr',
      accountId: botIdentity,
      threadId: `room/${senderIdentity}`,
      text: 'offline',
    }),
    /The Nostr relay target is unavailable/,
  );
});

test('a post while the socket is down is rejected as not sent', async () => {
  const { socket, transport, collect } = connectedTransport();
  await transport.poll?.(collect);
  socket.close();
  await assert.rejects(
    transport.post({
      channelId: 'nostr',
      accountId: botIdentity,
      threadId: `room/${senderIdentity}`,
      text: 'while down',
    }),
    (error: Error) => error instanceof MessagingNotSentError,
  );
});

test('returns the delivered ids when the attachment notice is not confirmed', async () => {
  const { socket, transport, collect } = connectedTransport();
  await transport.poll?.(collect);
  socket.open();

  const posted = transport.post({
    channelId: 'nostr',
    accountId: botIdentity,
    threadId: `room/${senderIdentity}`,
    text: 'body',
    attachments: [
      {
        name: 'report.pdf',
        mimeType: 'application/pdf',
        size: 3,
        async read() {
          return new Uint8Array([1, 2, 3]);
        },
      },
    ],
    attachmentFailure: async (names) => `Files stay in the app: ${names.join(', ')}`,
  });
  const textEvent = socket.frames('EVENT')[0][1] as NostrRelayEvent;
  socket.message(['OK', textEvent.id, true, '']);
  await sleep(0);
  const noticeEvent = socket.frames('EVENT')[1][1] as NostrRelayEvent;
  socket.message(['OK', noticeEvent.id, false, 'blocked']);
  assert.deepEqual(await posted, { id: textEvent.id, ids: [textEvent.id] });
});

test('rejects the post when the only notice is not confirmed', async () => {
  const { socket, transport, collect } = connectedTransport();
  await transport.poll?.(collect);
  socket.open();

  const alone = transport.post({
    channelId: 'nostr',
    accountId: botIdentity,
    threadId: `room/${senderIdentity}`,
    text: '',
    attachments: [
      {
        name: 'report.pdf',
        mimeType: 'application/pdf',
        size: 3,
        async read() {
          return new Uint8Array([1, 2, 3]);
        },
      },
    ],
    attachmentFailure: async (names) => `Files stay in the app: ${names.join(', ')}`,
  });
  await sleep(0);
  const noticeEvent = socket.frames('EVENT')[0][1] as NostrRelayEvent;
  socket.message(['OK', noticeEvent.id, false, 'blocked']);
  await assert.rejects(alone, /Nostr relay delivery was not confirmed/);
});

test('suppressed notice failure keeps no replay entry for a later identical notice', async () => {
  const { socket, transport, collect } = connectedTransport();
  await transport.poll?.(collect);
  socket.open();

  const post = (text: string) =>
    transport.post({
      channelId: 'nostr',
      accountId: botIdentity,
      threadId: `room/${senderIdentity}`,
      text,
      attachments: [
        {
          name: 'report.pdf',
          mimeType: 'application/pdf',
          size: 3,
          async read() {
            return new Uint8Array([1, 2, 3]);
          },
        },
      ],
      attachmentFailure: async (names) => `Files stay in the app: ${names.join(', ')}`,
    });

  const first = post('body');
  const textEvent = socket.frames('EVENT')[0][1] as NostrRelayEvent;
  socket.message(['OK', textEvent.id, true, '']);
  await sleep(0);
  const suppressedNotice = socket.frames('EVENT')[1][1] as NostrRelayEvent;
  socket.message(['OK', suppressedNotice.id, false, 'blocked']);
  assert.deepEqual(await first, { id: textEvent.id, ids: [textEvent.id] });

  const later = post('body');
  const laterText = socket.frames('EVENT')[2][1] as NostrRelayEvent;
  socket.message(['OK', laterText.id, true, '']);
  await sleep(0);
  const laterNotice = socket.frames('EVENT')[3][1] as NostrRelayEvent;
  assert.notEqual(laterNotice.id, suppressedNotice.id);
  socket.message(['OK', laterNotice.id, true, '']);
  assert.deepEqual(await later, { id: laterText.id, ids: [laterText.id, laterNotice.id] });
});

test('keeps the event id when a failed notice is retried', async () => {
  const { socket, transport, collect } = connectedTransport();
  await transport.poll?.(collect);
  socket.open();

  const post = () =>
    transport.post({
      channelId: 'nostr',
      accountId: botIdentity,
      threadId: `room/${senderIdentity}`,
      text: '',
      attachments: [
        {
          name: 'report.pdf',
          mimeType: 'application/pdf',
          size: 3,
          async read() {
            return new Uint8Array([1, 2, 3]);
          },
        },
      ],
      attachmentFailure: async (names) => `Files stay in the app: ${names.join(', ')}`,
    });

  const failed = post();
  await sleep(0);
  const attempt = socket.frames('EVENT')[0][1] as NostrRelayEvent;
  socket.message(['OK', attempt.id, false, 'blocked']);
  await assert.rejects(failed, /Nostr relay delivery was not confirmed/);

  const retry = post();
  await sleep(0);
  const replay = socket.frames('EVENT')[1][1] as NostrRelayEvent;
  assert.equal(replay.id, attempt.id);
  socket.message(['OK', replay.id, true, '']);
  assert.deepEqual(await retry, { id: attempt.id, ids: [attempt.id] });
});

test('backs off further while the relay keeps refusing the connection', async () => {
  const sockets: FakeSocket[] = [];
  const transport = createNostrRelayTransport(environment(), {
    createSocket: () => {
      const socket = new FakeSocket();
      sockets.push(socket);
      return socket;
    },
  });
  const collect = async (_message: InboundMessage) => {};
  await transport.poll?.(collect);
  sockets[0].open();
  sockets[0].message(['CLOSED', 'nod-nostr-relay', 'rate limited']);
  await sleep(1200);
  await transport.poll?.(collect);
  assert.equal(sockets.length, 2);
  sockets[1].open();
  sockets[1].message(['AUTH', 'challenge']);
  const auth = sockets[1].frames('AUTH')[0][1] as NostrRelayEvent;
  sockets[1].message(['OK', auth.id, false, 'denied']);
  await sleep(1200);
  await transport.poll?.(collect);
  assert.equal(sockets.length, 2);
  await sleep(1200);
  await transport.poll?.(collect);
  assert.equal(sockets.length, 3);
});

test('resets the reconnect delay after the relay accepts authentication', async () => {
  const sockets: FakeSocket[] = [];
  const transport = createNostrRelayTransport(environment(), {
    createSocket: () => {
      const socket = new FakeSocket();
      sockets.push(socket);
      return socket;
    },
  });
  const collect = async (_message: InboundMessage) => {};
  await transport.poll?.(collect);
  sockets[0].open();
  sockets[0].message(['CLOSED', 'nod-nostr-relay', 'auth-required: restricted']);
  await sleep(1200);
  await transport.poll?.(collect);
  sockets[1].open();
  sockets[1].message(['AUTH', 'challenge']);
  const auth = sockets[1].frames('AUTH')[0][1] as NostrRelayEvent;
  sockets[1].message(['OK', auth.id, true, '']);
  sockets[1].message(['CLOSED', 'nod-nostr-relay', 'rate limited']);
  await sleep(1200);
  await transport.poll?.(collect);
  assert.equal(sockets.length, 3);
});

test('resets the reconnect delay after the relay reports the subscription live', async () => {
  const sockets: FakeSocket[] = [];
  const transport = createNostrRelayTransport(environment(), {
    createSocket: () => {
      const socket = new FakeSocket();
      sockets.push(socket);
      return socket;
    },
  });
  const collect = async (_message: InboundMessage) => {};
  await transport.poll?.(collect);
  sockets[0].open();
  sockets[0].message(['CLOSED', 'nod-nostr-relay', 'rate limited']);
  await sleep(1200);
  await transport.poll?.(collect);
  sockets[1].open();
  sockets[1].message(['EOSE', 'nod-nostr-relay']);
  sockets[1].message(['CLOSED', 'nod-nostr-relay', 'rate limited']);
  await sleep(1200);
  await transport.poll?.(collect);
  assert.equal(sockets.length, 3);
});

test('drops replayed events older than the subscription cutoff', async () => {
  const { socket, transport, received, collect } = connectedTransport();
  await transport.poll?.(collect);
  socket.open();
  socket.message([
    'EVENT',
    'sub',
    signEvent(senderSecret, {
      kind: 9,
      created_at: Math.floor(Date.now() / 1000) - 60,
      tags: [
        ['h', 'room'],
        ['p', botIdentity],
      ],
      content: 'stale replay',
    }),
  ]);
  await transport.poll?.(collect);
  assert.equal(received.length, 0);
});

test('channel creation survives an unusable private key and keeps the other channels', () => {
  const existing: MessagingTransport = {
    channels: [{ id: 'telegram', status: 'configured', missing: [], allowedSenderIds: ['123'] }],
    receive: async () => ({ status: 404, body: { error: 'none' } }),
    post: async () => ({ id: 'x' }),
    close: async () => {},
  };
  for (const broken of [`0${'0'.repeat(63)}`, `f${'f'.repeat(63)}`]) {
    const transport = combineMessagingTransports(
      existing,
      createNostrRelayTransport({ ...environment(), NOSTR_PRIVATE_KEY: broken }),
    );
    assert.deepEqual(transport.channels[0], existing.channels[0]);
    const nostr = transport.channels.find((channel) => channel.id === 'nostr')!;
    assert.equal(nostr.status, 'setup_required');
    assert.deepEqual(nostr.missing, ['NOSTR_PRIVATE_KEY']);
    assert.equal(nostr.accountId, undefined);
    const disabled = createNostrRelayTransport({ NOSTR_PRIVATE_KEY: broken });
    assert.equal(disabled.channels[0].status, 'disabled');
    assert.equal(disabled.channels[0].accountId, undefined);
  }
});

type SettingsRow = {
  owner_id: string;
  provider: string;
  enabled: boolean;
  ciphertext: string | null;
  summary: Record<string, unknown>;
};

function settingsPool() {
  const rows: SettingsRow[] = [];
  const run = async (statement: string, values: unknown[] = []) => {
    const sql = statement.trim();
    if (sql.startsWith('INSERT INTO channel_settings')) {
      const [owner_id, provider, enabled, ciphertext, summary] = values as [
        string,
        string,
        boolean,
        string | null,
        string,
      ];
      const row: SettingsRow = {
        owner_id,
        provider,
        enabled,
        ciphertext,
        summary: JSON.parse(summary),
      };
      const index = rows.findIndex(
        (item) => item.owner_id === owner_id && item.provider === provider,
      );
      if (index < 0) rows.push(row);
      else rows[index] = row;
      return { rows: [], rowCount: 1 };
    }
    if (sql.startsWith('SELECT * FROM channel_settings WHERE owner_id'))
      return { rows: rows.filter((row) => row.owner_id === values[0]), rowCount: 0 };
    return { rows: [], rowCount: 0 };
  };
  return {
    query: run,
    async connect() {
      return { query: run, release() {} };
    },
  } as unknown as pg.Pool;
}

async function until(check: () => boolean) {
  const deadline = performance.now() + 3000;
  while (!check()) {
    if (performance.now() >= deadline)
      throw new Error('The setup did not reach the expected state.');
    await sleep(5);
  }
}

const setupSubscription = 'nod-nostr-setup';
const setupInput = {
  relayUrl: 'https://relay.example',
  privateKey: botSecret,
  channels: 'room',
  allowedPubkeys: senderIdentity,
};

function setupVerifier() {
  const sockets: FakeSocket[] = [];
  const verifier = createNostrRelaySetupVerifier({
    createSocket: () => {
      const socket = new FakeSocket();
      sockets.push(socket);
      return socket;
    },
  });
  const last = async () => {
    await until(() => sockets.length > 0);
    return sockets.at(-1)!;
  };
  const accept = async (index: number) => {
    await until(() => sockets.length > index);
    const socket = sockets[index];
    socket.open();
    socket.message(['EOSE', setupSubscription]);
  };
  return { sockets, verifier, last, accept };
}

test('the relay setup verifies the connection before it saves the settings', async () => {
  const pool = settingsPool();
  const { verifier, last } = setupVerifier();
  const applied: Record<string, string>[] = [];
  const settings = await createChannelSettings(pool, {
    ownerId: 'nostr-setup-fixture',
    keyStore: { id: 'fixture', configured: true, getKey: async () => randomBytes(32) },
    verifier,
    apply: async (environment) => {
      applied.push({ ...environment });
    },
  });
  const app = Fastify();
  settings.registerRoutes(app);
  try {
    const pending = app.inject({
      method: 'PUT',
      url: '/api/channel-settings/nostr',
      payload: { ...setupInput, channels: 'room, hall' },
    });
    const socket = await last();
    socket.open();
    const request = socket.frames('REQ')[0];
    assert.equal(request[1], setupSubscription);
    const filter = request[2] as Record<string, unknown>;
    assert.deepEqual(filter['#h'], ['room', 'hall']);
    assert.deepEqual(filter['#p'], [botIdentity]);
    socket.message(['AUTH', 'setup-challenge']);
    const auth = socket.frames('AUTH')[0][1] as NostrRelayEvent;
    assert.equal(auth.kind, 22242);
    assert.deepEqual(auth.tags, [
      ['challenge', 'setup-challenge'],
      ['relay', 'wss://relay.example'],
    ]);
    assert.ok(verifyEvent(auth));
    socket.message(['OK', auth.id, true, '']);
    assert.equal(socket.frames('REQ').length, 2);
    socket.message(['EOSE', setupSubscription]);
    const response = await pending;
    assert.equal(response.statusCode, 200);
    assert.deepEqual(response.json().channel, {
      provider: 'nostr',
      enabled: true,
      accountName: 'relay.example',
      accountHandle: 'wss://relay.example',
    });
    assert.equal(response.body.includes(botSecret), false);
    assert.equal(socket.closed, true);
    const environment = await settings.environment();
    assert.equal(environment.NOSTR_ENABLED, 'true');
    assert.equal(environment.NOSTR_RELAY_URL, 'https://relay.example');
    assert.equal(environment.NOSTR_PRIVATE_KEY, botSecret);
    assert.equal(environment.NOSTR_CHANNELS, 'room,hall');
    assert.equal(environment.NOSTR_ALLOWED_PUBKEYS, senderIdentity);
    assert.deepEqual(applied, [environment]);
  } finally {
    await app.close();
  }
});

test('a refused or failed relay setup keeps its reason and never shows the private key', async () => {
  const { verifier, last } = setupVerifier();
  const verify = () => verifier.verify('nostr', setupInput);

  const refused = verify();
  let socket = await last();
  socket.open();
  socket.message(['AUTH', 'challenge-1']);
  const auth = socket.frames('AUTH')[0][1] as NostrRelayEvent;
  socket.message(['OK', auth.id, false, `restricted: auth failed ${botSecret}`]);
  await assert.rejects(refused, (error: Error) => {
    assert.ok(error instanceof ChannelSetupFailure);
    assert.equal(error.reason, 'verification_failed');
    assert.match(error.details ?? '', /restricted: auth failed/);
    assert.match(error.details ?? '', /\[redacted\]/);
    assert.equal(error.details?.includes(botSecret), false);
    return true;
  });

  const closed = verify();
  socket = await last();
  socket.open();
  socket.message(['CLOSED', setupSubscription, 'auth-required: restricted']);
  await assert.rejects(closed, (error: Error) => {
    assert.ok(error instanceof ChannelSetupFailure);
    assert.equal(error.reason, 'verification_failed');
    assert.match(error.details ?? '', /auth-required: restricted/);
    return true;
  });

  const dropped = verify();
  socket = await last();
  socket.close();
  await assert.rejects(dropped, (error: Error) => {
    assert.ok(error instanceof ChannelSetupFailure);
    assert.equal(error.reason, 'verification_failed');
    assert.match(error.details ?? '', /closed the connection/);
    return true;
  });

  const unopenable = createNostrRelaySetupVerifier({
    createSocket: () => {
      throw new Error('socket refused');
    },
  });
  await assert.rejects(unopenable.verify('nostr', setupInput), (error: Error) => {
    assert.ok(error instanceof ChannelSetupFailure);
    assert.equal(error.reason, 'verification_failed');
    assert.match(error.details ?? '', /connection failed/);
    return true;
  });
});

test('the relay setup ignores a CLOSED while its authentication is pending', async () => {
  const { verifier, last } = setupVerifier();
  const pending = verifier.verify('nostr', setupInput);
  const socket = await last();
  socket.open();
  socket.message(['AUTH', 'setup-challenge']);
  const auth = socket.frames('AUTH')[0][1] as NostrRelayEvent;
  socket.message(['CLOSED', setupSubscription, 'auth-required: restricted']);
  socket.message(['OK', auth.id, true, '']);
  assert.equal(socket.frames('REQ').length, 2);
  socket.message(['EOSE', setupSubscription]);
  const result = await pending;
  assert.equal(result.environment.NOSTR_CHANNELS, 'room');
});

test('the relay setup probe requests no stored conversation history', async () => {
  const { verifier, last } = setupVerifier();
  const started = Math.floor(Date.now() / 1000);
  const pending = verifier.verify('nostr', setupInput);
  const socket = await last();
  socket.open();
  const filter = socket.frames('REQ')[0][2] as Record<string, unknown>;
  socket.message(['EOSE', setupSubscription]);
  await pending;
  assert.equal(typeof filter.since, 'number');
  assert.ok(Number.isInteger(filter.since));
  assert.ok((filter.since as number) >= started);
  assert.ok((filter.since as number) <= Math.floor(Date.now() / 1000));
});

test('an unusable setup value names the field to correct and never an environment name', async () => {
  const { sockets, verifier } = setupVerifier();
  await assert.rejects(
    verifier.verify('nostr', { ...setupInput, relayUrl: 'ftp://relay.example' }),
    (error: Error) => {
      assert.ok(error instanceof ChannelSetupFailure);
      assert.equal(error.reason, 'invalid_input');
      assert.match(error.details ?? '', /relay address/);
      assert.equal(error.details?.includes('NOSTR_'), false);
      return true;
    },
  );
  await assert.rejects(
    verifier.verify('nostr', { ...setupInput, privateKey: 'not-a-key' }),
    (error: Error) => {
      assert.ok(error instanceof ChannelSetupFailure);
      assert.equal(error.reason, 'invalid_input');
      assert.match(error.details ?? '', /private key/);
      assert.equal(error.details?.includes('NOSTR_'), false);
      return true;
    },
  );
  await assert.rejects(
    verifier.verify('nostr', {
      relayUrl: setupInput.relayUrl,
      privateKey: setupInput.privateKey,
      channels: setupInput.channels,
    }),
    (error: Error) => {
      assert.ok(error instanceof ChannelSetupFailure);
      assert.equal(error.reason, 'invalid_input');
      assert.match(error.details ?? '', /allowed pubkeys/);
      assert.equal(error.details?.includes('NOSTR_'), false);
      return true;
    },
  );
  assert.equal(sockets.length, 0);
});

test('the relay setup validates its input before it opens a connection', async () => {
  const { sockets, verifier } = setupVerifier();
  for (const input of [
    { ...setupInput, relayUrl: 'ftp://relay.example' },
    { ...setupInput, privateKey: 'not-a-key' },
    { ...setupInput, channels: ' ' },
    { ...setupInput, allowedPubkeys: 'not-a-key' },
    { ...setupInput, allowedPubkeys: ' ' },
    { relayUrl: 'https://relay.example' },
    { ...setupInput, unexpected: true },
  ])
    await assert.rejects(verifier.verify('nostr', input), (error: Error) => {
      assert.ok(error instanceof ChannelSetupFailure);
      assert.equal(error.reason, 'invalid_input');
      assert.ok(error.details);
      return true;
    });
  assert.equal(sockets.length, 0);
});

test('saved relay settings reload and feed the transport', async () => {
  const pool = settingsPool();
  const { verifier, accept } = setupVerifier();
  const key = randomBytes(32);
  const keyStore = { id: 'fixture', configured: true, getKey: async () => key };
  const first = await createChannelSettings(pool, {
    ownerId: 'nostr-settings-fixture',
    keyStore,
    verifier,
    apply: async () => {},
  });
  const app = Fastify();
  first.registerRoutes(app);
  try {
    const index = 0;
    const pending = app.inject({
      method: 'PUT',
      url: '/api/channel-settings/nostr',
      payload: setupInput,
    });
    await accept(index);
    assert.equal((await pending).statusCode, 200);
  } finally {
    await app.close();
  }
  const transport = createNostrRelayTransport(await first.environment());
  assert.equal(transport.channels[0].status, 'configured');
  assert.equal(transport.channels[0].accountId, botIdentity);
  assert.deepEqual(transport.channels[0].allowedSenderIds, [senderIdentity]);

  const reloaded = await createChannelSettings(pool, {
    ownerId: 'nostr-settings-fixture',
    keyStore,
    verifier,
    apply: async () => {},
  });
  const status = await reloaded.status();
  assert.deepEqual(
    status.channels.find((item) => item.provider === 'nostr'),
    {
      provider: 'nostr',
      enabled: true,
      accountName: 'relay.example',
      accountHandle: 'wss://relay.example',
    },
  );
  assert.equal(JSON.stringify(status).includes(botSecret), false);
  const restored = await reloaded.environment();
  assert.equal(restored.NOSTR_PRIVATE_KEY, botSecret);
  assert.equal(createNostrRelayTransport(restored).channels[0].status, 'configured');
});

test('a managed relay configuration keeps its configured state and shadows saved settings', async () => {
  const pilot = {
    NOSTR_ENABLED: 'true',
    NOSTR_RELAY_URL: 'https://relay.example',
    NOSTR_PRIVATE_KEY: botSecret,
    NOSTR_CHANNELS: 'room',
    NOSTR_ALLOWED_PUBKEYS: senderIdentity,
  };
  const pool = settingsPool();
  const key = randomBytes(32);
  const keyStore = { id: 'fixture', configured: true, getKey: async () => key };
  const isolated = await createChannelSettings(pool, {
    ownerId: 'nostr-env-fixture',
    keyStore,
    verifier: setupVerifier().verifier,
    managed: managedChannelEnvironment(pilot),
    apply: async () => {},
  });
  const environment = await isolated.environment();
  assert.equal(createNostrRelayTransport(environment).channels[0].status, 'configured');
  const managedChannel = (await isolated.status()).channels.find(
    (item) => item.provider === 'nostr',
  );
  assert.deepEqual(managedChannel, {
    provider: 'nostr',
    enabled: true,
    managed: true,
  });
  assert.equal(JSON.stringify(await isolated.status()).includes(botSecret), false);

  const { verifier, accept } = setupVerifier();
  const saved = await createChannelSettings(pool, {
    ownerId: 'nostr-env-fixture',
    keyStore,
    verifier,
    apply: async () => {},
  });
  const app = Fastify();
  saved.registerRoutes(app);
  try {
    const index = 0;
    const pending = app.inject({
      method: 'PUT',
      url: '/api/channel-settings/nostr',
      payload: { ...setupInput, privateKey: senderSecret },
    });
    await accept(index);
    assert.equal((await pending).statusCode, 200);
  } finally {
    await app.close();
  }
  const shadowing = await createChannelSettings(pool, {
    ownerId: 'nostr-env-fixture',
    keyStore: {
      id: 'fixture',
      configured: true,
      getKey: async () => {
        throw new Error('Managed settings must not decrypt saved credentials.');
      },
    },
    verifier,
    managed: managedChannelEnvironment(pilot),
    apply: async () => {
      throw new Error('Managed settings must not rewrite the environment.');
    },
  });
  const shadowed = await shadowing.environment();
  assert.equal(shadowed.NOSTR_PRIVATE_KEY, botSecret);
  assert.equal(shadowed.NOSTR_ALLOWED_PUBKEYS, senderIdentity);
  assert.equal(createNostrRelayTransport(shadowed).channels[0].status, 'configured');
  const refuse = Fastify();
  shadowing.registerRoutes(refuse);
  try {
    for (const method of ['PUT', 'DELETE'] as const)
      assert.equal(
        (
          await refuse.inject({
            method,
            url: '/api/channel-settings/nostr',
            ...(method === 'PUT' ? { payload: setupInput } : {}),
          })
        ).statusCode,
        409,
      );
  } finally {
    await refuse.close();
  }
});

test('the channel status masking follows the saved and managed configuration', async () => {
  const pool = settingsPool();
  const { sockets, verifier, accept } = setupVerifier();
  const key = randomBytes(32);
  const keyStore = { id: 'fixture', configured: true, getKey: async () => key };
  const settings = await createChannelSettings(pool, {
    ownerId: 'nostr-masking-fixture',
    keyStore,
    verifier,
    apply: async () => {},
  });
  const app = Fastify();
  settings.registerRoutes(app);
  const save = async (payload: object) => {
    const index = sockets.length;
    const pending = app.inject({ method: 'PUT', url: '/api/channel-settings/nostr', payload });
    await accept(index);
    return pending;
  };
  try {
    assert.equal(
      createNostrRelayTransport(await settings.environment()).channels[0].status,
      'disabled',
    );

    const refused = await app.inject({
      method: 'PUT',
      url: '/api/channel-settings/nostr',
      payload: {
        relayUrl: setupInput.relayUrl,
        privateKey: setupInput.privateKey,
        channels: setupInput.channels,
      },
    });
    assert.equal(refused.statusCode, 400);
    assert.match(String(refused.json().error), /allowed pubkeys/);
    assert.equal(refused.body.includes(setupInput.privateKey), false);
    assert.equal(
      createNostrRelayTransport(await settings.environment()).channels[0].status,
      'disabled',
    );

    assert.equal((await save(setupInput)).statusCode, 200);
    assert.equal(
      createNostrRelayTransport(await settings.environment()).channels[0].status,
      'configured',
    );

    assert.equal(
      (await app.inject({ method: 'DELETE', url: '/api/channel-settings/nostr' })).statusCode,
      200,
    );
    assert.equal(
      createNostrRelayTransport(await settings.environment()).channels[0].status,
      'disabled',
    );

    const managed = await createChannelSettings(pool, {
      ownerId: 'nostr-masking-fixture',
      keyStore,
      verifier,
      managed: managedChannelEnvironment({ NOSTR_ENABLED: 'true' }),
      apply: async () => {},
    });
    const missing = createNostrRelayTransport(await managed.environment()).channels[0];
    assert.equal(missing.status, 'setup_required');
    assert.deepEqual([...missing.missing].sort(), [
      'NOSTR_ALLOWED_PUBKEYS',
      'NOSTR_PRIVATE_KEY',
      'NOSTR_RELAY_URL',
    ]);

    const variablesOnly = await createChannelSettings(pool, {
      ownerId: 'nostr-masking-fixture',
      keyStore,
      verifier,
      managed: managedChannelEnvironment({ NOSTR_RELAY_URL: 'https://relay.example' }),
      apply: async () => {},
    });
    assert.equal(
      createNostrRelayTransport(await variablesOnly.environment()).channels[0].status,
      'disabled',
    );
  } finally {
    await app.close();
  }
});
