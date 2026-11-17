import { useRef, useState } from 'react';
import type { ChannelSetupSummary } from '../../shared/contracts';
import { Check } from './icons';
import { Button, Checkbox, Field, Input, Notice } from './ui';

const steps = ['Add your Buzz', 'Add key', 'Choose channels', 'Confirm'];

export function NostrSetup({
  setup,
  fields,
  busy,
  error,
  unavailable = false,
  onField,
  onVerify,
}: {
  setup?: ChannelSetupSummary;
  fields: Record<string, string>;
  busy: boolean;
  error: string;
  unavailable?: boolean;
  onField(name: string, value: string): void;
  onVerify(event: React.FormEvent): void;
}) {
  const [step, setStep] = useState(0);
  const [accepted, setAccepted] = useState(false);
  const relayUrl = useRef<HTMLInputElement>(null);
  const privateKey = useRef<HTMLInputElement>(null);
  const disabled = busy || unavailable;
  const filled = [
    Boolean(fields.relayUrl?.trim()),
    Boolean(fields.privateKey?.trim()),
    Boolean(fields.channels?.trim()) && accepted,
  ];
  const complete = filled.every(Boolean);
  const setupError =
    error ||
    (unavailable && !setup?.managed ? 'Set up Nod’s secure key store to connect Buzz.' : '');
  function continueTo(next: number) {
    return (event: React.FormEvent) => {
      event.preventDefault();
      if (!disabled) setStep(next);
    };
  }
  return (
    <div className="nostr-setup">
      {setupError && <Notice>{setupError}</Notice>}
      {setup?.managed && (
        <p>Buzz is managed by the server environment. Change its settings there and restart Nod.</p>
      )}
      {setup?.managed ? null : (
        <ol className="nostr-setup-steps">
          {steps.map((title, index) => {
            const active = step === index;
            const done = step > index;
            return (
              <li
                key={title}
                data-state={done ? 'done' : active ? 'active' : 'next'}
                aria-current={active ? 'step' : undefined}
              >
                <span className="nostr-setup-marker" aria-hidden="true">
                  {done ? <Check size={14} /> : index + 1}
                </span>
                <div className="nostr-setup-step">
                  <strong>{title}</strong>
                  {active && index === 0 && (
                    <form className="nostr-setup-content" onSubmit={continueTo(1)}>
                      <p>Open your Buzz settings and copy its address.</p>
                      <Button
                        type="button"
                        size="sm"
                        disabled={disabled}
                        onClick={() => relayUrl.current?.focus()}
                      >
                        I have my address
                      </Button>
                      <Field
                        label="Relay URL"
                        hint="Use an https, http, wss or ws address, such as wss://relay.example."
                      >
                        <Input
                          ref={relayUrl}
                          type="url"
                          required
                          spellCheck={false}
                          placeholder="wss://relay.example"
                          disabled={disabled}
                          value={fields.relayUrl ?? ''}
                          onChange={(event) => onField('relayUrl', event.target.value)}
                        />
                      </Field>
                      <div className="nostr-setup-actions">
                        <Button type="submit" size="sm" disabled={disabled || !filled[0]}>
                          Continue
                        </Button>
                      </div>
                    </form>
                  )}
                  {active && index === 1 && (
                    <form className="nostr-setup-content" onSubmit={continueTo(2)}>
                      <p>Copy the key of the account Nod should use.</p>
                      <Button
                        type="button"
                        size="sm"
                        disabled={disabled}
                        onClick={() => privateKey.current?.focus()}
                      >
                        I have my key
                      </Button>
                      <Field
                        label="Private key"
                        hint="Nod signs its events with this 64-hex key and saves it encrypted."
                      >
                        <Input
                          ref={privateKey}
                          type="password"
                          autoComplete="off"
                          required
                          spellCheck={false}
                          placeholder="a1b2c3…"
                          data-analytics-private
                          disabled={disabled}
                          value={fields.privateKey ?? ''}
                          onChange={(event) => onField('privateKey', event.target.value)}
                        />
                      </Field>
                      <div className="nostr-setup-actions">
                        <Button type="submit" size="sm" disabled={disabled || !filled[1]}>
                          Continue
                        </Button>
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          disabled={busy}
                          onClick={() => setStep(0)}
                        >
                          Back
                        </Button>
                      </div>
                    </form>
                  )}
                  {active && index === 2 && (
                    <form className="nostr-setup-content" onSubmit={continueTo(3)}>
                      <Field label="Channels" hint="Comma-separated channel IDs Nod listens in.">
                        <Input
                          required
                          spellCheck={false}
                          placeholder="room"
                          disabled={disabled}
                          value={fields.channels ?? ''}
                          onChange={(event) => onField('channels', event.target.value)}
                        />
                      </Field>
                      <Field
                        label="Allowed pubkeys"
                        hint="Optional. Comma-separated 64-hex pubkeys; Nod answers no one else."
                      >
                        <Input
                          spellCheck={false}
                          placeholder="a1b2c3…"
                          data-analytics-private
                          disabled={disabled}
                          value={fields.allowedPubkeys ?? ''}
                          onChange={(event) => onField('allowedPubkeys', event.target.value)}
                        />
                      </Field>
                      <label className="channel-policy">
                        <Checkbox
                          checked={accepted}
                          required
                          disabled={disabled}
                          onChange={(event) => setAccepted(event.target.checked)}
                        />
                        <span>
                          Anyone who can post in the channel can reach Nod. Only add channels you
                          trust.
                        </span>
                      </label>
                      <div className="nostr-setup-actions">
                        <Button type="submit" size="sm" disabled={disabled || !filled[2]}>
                          Continue
                        </Button>
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          disabled={busy}
                          onClick={() => setStep(1)}
                        >
                          Back
                        </Button>
                      </div>
                    </form>
                  )}
                  {active && index === 3 && (
                    <form className="nostr-setup-content" onSubmit={onVerify}>
                      <p>Nod answers in the channels you chose.</p>
                      <div className="nostr-setup-actions">
                        <Button type="submit" size="sm" disabled={disabled || !complete}>
                          {busy ? 'Connecting…' : 'Connect Buzz'}
                        </Button>
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          disabled={busy}
                          onClick={() => setStep(2)}
                        >
                          Back
                        </Button>
                      </div>
                    </form>
                  )}
                </div>
              </li>
            );
          })}
        </ol>
      )}
    </div>
  );
}
