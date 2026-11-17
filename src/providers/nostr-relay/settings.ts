import { z } from 'zod';
import { ChannelSetupFailure, type ChannelSetupVerifier } from '../../ports/channel-settings.ts';
import { configuration as relayConfiguration, signEvent, type RelaySocket } from './index.ts';

const authKind = 22242;
const chatKind = 9;
const setupSubscription = 'nod-nostr-setup';
const setupTimeoutMs = 15_000;

const inputSchema = z
  .object({
    relayUrl: z.string().trim().min(1).max(200),
    privateKey: z.string().trim().min(1).max(512),
    channels: z.string().trim().min(1).max(1000),
    allowedPubkeys: z.string().trim().max(5000).optional(),
  })
  .strict();

function withoutSecret(message: string, secrets: string[]) {
  let text = message;
  for (const secret of secrets)
    for (const value of [secret, encodeURIComponent(secret)])
      if (value) text = text.replaceAll(value, '[redacted]');
  return text;
}

function relayReason(value: unknown) {
  return typeof value === 'string' && value.trim() ? value.trim() : 'no reason given';
}

function probe(
  config: {
    relayUrl: string;
    secretKey: string;
    accountId: string;
    relayChannels: string[];
  },
  createSocket: ((url: string) => RelaySocket) | undefined,
  secrets: string[],
) {
  let socket: RelaySocket;
  try {
    socket = (createSocket ?? ((url: string) => new WebSocket(url)))(config.relayUrl);
  } catch {
    throw new ChannelSetupFailure(
      'verification_failed',
      'The relay connection failed. Check the relay address.',
    );
  }
  return new Promise<void>((resolve, reject) => {
    let settled = false;
    let pendingAuthentication: string | undefined;
    const finish = (failure?: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.close();
      if (failure)
        reject(new ChannelSetupFailure('verification_failed', withoutSecret(failure, secrets)));
      else resolve();
    };
    const timer = setTimeout(
      () => finish('The relay did not answer the subscription request within 15 seconds.'),
      setupTimeoutMs,
    );
    timer.unref?.();
    const send = (frame: unknown[]) => socket.send(JSON.stringify(frame));
    const subscribe = () =>
      send([
        'REQ',
        setupSubscription,
        { kinds: [chatKind], '#h': config.relayChannels, '#p': [config.accountId] },
      ]);
    socket.addEventListener('open', subscribe);
    socket.addEventListener('error', () =>
      finish('The relay connection failed. Check the relay address.'),
    );
    socket.addEventListener('close', () =>
      finish('The relay closed the connection before it confirmed the subscription.'),
    );
    socket.addEventListener('message', (event) => {
      if (typeof event.data !== 'string') return;
      let message: unknown;
      try {
        message = JSON.parse(event.data);
      } catch {
        return;
      }
      if (!Array.isArray(message) || typeof message[0] !== 'string') return;
      const [type] = message;
      if (type === 'AUTH') {
        const challenge = message[1];
        if (typeof challenge !== 'string' || !challenge)
          return finish('The relay sent an empty authentication challenge.');
        const authentication = signEvent(config.secretKey, {
          kind: authKind,
          tags: [
            ['challenge', challenge],
            ['relay', config.relayUrl],
          ],
          content: '',
          created_at: Math.floor(Date.now() / 1000),
        });
        pendingAuthentication = authentication.id;
        send(['AUTH', authentication]);
        return;
      }
      if (type === 'OK') {
        if (message[1] !== pendingAuthentication) return;
        if (message[2] !== true)
          return finish(`The relay refused authentication: ${relayReason(message[3])}`);
        pendingAuthentication = undefined;
        subscribe();
        return;
      }
      if (type === 'EOSE' && message[1] === setupSubscription) return finish();
      if (type === 'CLOSED' && message[1] === setupSubscription)
        return finish(`The relay refused the subscription: ${relayReason(message[2])}`);
    });
  });
}

export function createNostrRelaySetupVerifier(
  options: { createSocket?: (url: string) => RelaySocket } = {},
): ChannelSetupVerifier {
  return {
    async verify(provider, input): ReturnType<ChannelSetupVerifier['verify']> {
      if (provider !== 'nostr')
        throw new ChannelSetupFailure('invalid_input', 'This setup verifies a Nostr relay.');
      const parsed = inputSchema.safeParse(input);
      if (!parsed.success)
        throw new ChannelSetupFailure(
          'invalid_input',
          'Enter the relay address, a 64-hex private key and the channel IDs as text.',
        );
      const value = parsed.data;
      const config = relayConfiguration({
        NOSTR_ENABLED: 'true',
        NOSTR_RELAY_URL: value.relayUrl,
        NOSTR_PRIVATE_KEY: value.privateKey,
        NOSTR_CHANNELS: value.channels,
        NOSTR_ALLOWED_PUBKEYS: value.allowedPubkeys ?? '',
      });
      const missing = config.missing.filter(
        (name) => name !== 'NOSTR_ALLOWED_PUBKEYS' || Boolean(value.allowedPubkeys?.trim()),
      );
      const relayUrl = config.relayUrl;
      const secretKey = config.secretKey;
      const accountId = config.accountId;
      if (missing.length || !relayUrl || !secretKey || !accountId)
        throw new ChannelSetupFailure(
          'invalid_input',
          `The Nostr relay setup is missing ${missing.join(', ') || 'NOSTR_PRIVATE_KEY'}.`,
        );
      await probe(
        { relayUrl, secretKey, accountId, relayChannels: config.relayChannels },
        options.createSocket,
        [value.privateKey],
      );
      return {
        environment: {
          NOSTR_ENABLED: 'true',
          NOSTR_RELAY_URL: value.relayUrl,
          NOSTR_PRIVATE_KEY: secretKey,
          NOSTR_CHANNELS: config.relayChannels.join(','),
          NOSTR_ALLOWED_PUBKEYS: config.allowedSenderIds.join(','),
        },
        summary: {
          provider: 'nostr',
          enabled: true,
          accountName: new URL(relayUrl).host,
          accountHandle: relayUrl,
        },
      };
    },
  };
}
