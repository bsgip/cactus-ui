import { Button, Flex, Heading, Link, Separator, Text, TextField } from '@radix-ui/themes';
import { IconCheck, IconDownload, IconPencil } from '@tabler/icons-react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState, type ComponentProps, type ReactNode } from 'react';
import { updateDomain, updatePen } from '../../api/config';
import { InfoPopover } from '../../components/InfoPopover';
import { SectionCard } from '../../components/SectionCard';
import { useConfirm } from '../../components/useConfirm';

// Account-wide settings that sit above run groups: the organisation identity baked into every
// issued certificate (PEN, notification domain) and the utility-server trust bundle an aggregator
// webhook needs to accept notifications. Grouped here so "set up once per organisation" actions
// are separated from the per-device run group workflow below.
export function OrganisationCard({
  pen,
  domain,
  setError,
}: {
  pen: number | null;
  domain: string;
  setError: (msg: string | null) => void;
}) {
  return (
    <SectionCard title="Organisation Setup">
      <Text as="p" mb="3" color="gray">
        These settings apply account-wide: your identity is embedded in every certificate you
        generate below, and the notification settings control how the utility server delivers
        subscription notifications to you.
      </Text>

      <Flex direction="column" gap="4">
        <SaveField
          label="Private Enterprise Number (PEN) — Optional"
          infoTitle="Private Enterprise Number (PEN)"
          info={
            <>
              A PEN is a numeric identifier IANA assigns to an organisation. CSIP-Aus requires
              clients to encode a PEN in various requests, and CACTUS embeds it in every issued
              certificate (as the hardware-module <em>hwType</em> OID). Leave blank to use the
              reserved value <strong>0</strong>. Obtain one for free from{' '}
              <Link href="https://www.iana.org/assignments/enterprise-numbers/" target="_blank">
                IANA
              </Link>
              .
            </>
          }
          savedValue={pen != null ? String(pen) : ''}
          placeholder="e.g. 123456"
          emptyHint="Not set — certificates will use the reserved value 0."
          saveLabel="Save PEN"
          confirmTitle="Update your PEN?"
          confirmBody="Your PEN is embedded in every certificate you generate. Existing certificates keep the old PEN — you will need to manually regenerate them for the change to take effect."
          inputProps={{ type: 'number', min: 1, max: 4294967295 }}
          save={(value) => updatePen(Number(value))}
          setError={setError}
        />

        <Separator size="4" />

        <Flex direction="column" gap="1">
          <Heading as="h4" size="2">
            Subscription Notifications
          </Heading>
          <Text size="2" color="gray">
            For aggregators that subscribe to resources: the utility server delivers notifications
            to your webhook over mutual TLS. Register your webhook&apos;s domain here, and install
            the utility server certificates in your webhook&apos;s trust store.
          </Text>
        </Flex>

        <SaveField
          label="Notification Domain — Optional (required for aggregator certificates)"
          infoTitle="Notification Domain"
          info={
            <>
              The fully-qualified domain of your webhook endpoint. The utility server (envoy) uses
              it to send subscription notifications back to you over mutual TLS, so it is baked into
              the SAN of any <strong>aggregator</strong> certificate you generate and is checked
              when notifications are delivered. Device certificates do not use it. All subscription
              notification URIs must use this registered domain or they will be rejected.
            </>
          }
          savedValue={domain}
          placeholder="e.g. my.example.com"
          emptyHint="Not set — aggregator certificates cannot be generated until a domain is registered."
          saveLabel="Save Domain"
          confirmTitle="Update the notification domain?"
          confirmBody="Your certificates must whitelist the subscription domain — changing it means you will need to manually regenerate your existing aggregator certificates before notifications can be delivered."
          save={(value) => updateDomain(value)}
          setError={setError}
        />

        <Flex direction="column" gap="2">
          <Flex align="center" gap="1">
            <Text weight="bold" size="2">
              Utility Server Certificates
            </Text>
            <InfoPopover title="Utility Server Certificates">
              When the utility server (envoy) sends subscription notifications to your webhook it
              connects as a TLS client and presents its own certificate. To accept those connections
              your webhook must trust them. This bundle contains:
              <ul style={{ margin: '0.5rem 0 0', paddingLeft: '1.1rem' }}>
                <li>
                  <strong>serca.pem</strong> — the root trust anchor; install it in your
                  webhook&apos;s trust store.
                </li>
                <li>
                  <strong>utility-server-fullchain.pem</strong> — the utility server&apos;s identity
                  chain (excluding the root).
                </li>
              </ul>
            </InfoPopover>
          </Flex>
          <Flex>
            <Button asChild variant="outline">
              <a href="/config/ca_cert">
                <IconDownload size={14} />
                Download Utility Server Certificates
              </a>
            </Button>
          </Flex>
        </Flex>
      </Flex>
    </SectionCard>
  );
}

// A labelled input + save button with explicit state feedback: the button only enables once the
// value differs from what is saved, an "Unsaved changes" hint appears while dirty, and a green
// "Saved" indicator confirms a successful save. Overwriting an already-set value asks for
// confirmation first, since both identity values are baked into previously issued certificates.
function SaveField({
  label,
  infoTitle,
  info,
  savedValue,
  placeholder,
  emptyHint,
  saveLabel,
  confirmTitle,
  confirmBody,
  inputProps,
  save,
  setError,
}: {
  label: string;
  infoTitle: string;
  info: ReactNode;
  savedValue: string;
  placeholder: string;
  emptyHint: string;
  saveLabel: string;
  confirmTitle: string;
  confirmBody: string;
  inputProps?: ComponentProps<typeof TextField.Root>;
  save: (value: string) => Promise<unknown>;
  setError: (msg: string | null) => void;
}) {
  const queryClient = useQueryClient();
  const { confirm, confirmDialog } = useConfirm();
  const [value, setValue] = useState(savedValue);
  // Tracked locally (rather than relying on the refetched prop) so the dirty/saved indicators
  // update the moment the mutation succeeds, not when the config query settles.
  const [lastSaved, setLastSaved] = useState(savedValue);
  const isDirty = value !== lastSaved;

  const mutation = useMutation({
    mutationFn: () => save(value),
    onSuccess: () => {
      setError(null);
      setLastSaved(value);
      void queryClient.invalidateQueries({ queryKey: ['config'] });
    },
    onError: (err: Error) => setError(err.message),
  });

  const handleSave = () => {
    if (lastSaved) {
      confirm({
        title: confirmTitle,
        body: confirmBody,
        confirmLabel: 'Update',
        confirmColor: 'red',
        onConfirm: () => mutation.mutate(),
      });
    } else {
      mutation.mutate();
    }
  };

  const showSaved = mutation.isSuccess && !isDirty;

  return (
    <Flex direction="column" gap="2">
      <Flex align="center" gap="1">
        <Text as="label" weight="bold" size="2">
          {label}
        </Text>
        <InfoPopover title={infoTitle}>{info}</InfoPopover>
      </Flex>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (isDirty) handleSave();
        }}
      >
        <Flex gap="2" align="center">
          <TextField.Root
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={placeholder}
            style={{ flex: 1 }}
            {...inputProps}
          />
          <Button type="submit" disabled={!isDirty} loading={mutation.isPending}>
            <IconPencil size={14} />
            {saveLabel}
          </Button>
        </Flex>
      </form>
      {isDirty ? (
        <Text size="1" color="orange">
          Unsaved changes — click &ldquo;{saveLabel}&rdquo; to apply.
        </Text>
      ) : showSaved ? (
        <Flex align="center" gap="1">
          <IconCheck size={14} color="var(--green-9)" />
          <Text size="1" color="green">
            Saved
          </Text>
        </Flex>
      ) : !lastSaved ? (
        <Text size="1" color="gray">
          {emptyHint}
        </Text>
      ) : null}
      {confirmDialog}
    </Flex>
  );
}
