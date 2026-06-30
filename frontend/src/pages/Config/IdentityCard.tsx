import { Button, Flex, Link, Text, TextField } from '@radix-ui/themes';
import { IconPencil } from '@tabler/icons-react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { updateDomain, updatePen } from '../../api/config';
import { InfoPopover } from '../../components/InfoPopover';
import { SectionCard } from '../../components/SectionCard';

// Account-level identity that feeds every issued certificate: the PEN (baked into each cert) and
// the notification domain (baked into aggregator cert SANs and used by the utility server for
// outbound notification mTLS). Both are optional in general, but the domain is mandatory before an
// aggregator certificate can be generated.
export function IdentityCard({
  pen,
  domain,
  setError,
}: {
  pen: number | null;
  domain: string;
  setError: (msg: string | null) => void;
}) {
  const queryClient = useQueryClient();
  const [penValue, setPenValue] = useState<string>(pen != null ? String(pen) : '');
  const [domainValue, setDomainValue] = useState(domain);

  const onSuccess = () => {
    setError(null);
    void queryClient.invalidateQueries({ queryKey: ['config'] });
  };
  const onError = (err: Error) => setError(err.message);

  const penMutation = useMutation({ mutationFn: () => updatePen(Number(penValue)), onSuccess, onError });
  const domainMutation = useMutation({ mutationFn: () => updateDomain(domainValue), onSuccess, onError });

  return (
    <SectionCard title="Organisation Identity">
      <Text as="p" mb="3" color="gray">
        These values identify your organisation and are embedded in the certificates you generate
        below. Both are optional, but a notification domain is required before generating an
        aggregator certificate.
      </Text>

      <Flex direction="column" gap="4">
        <Flex direction="column" gap="2">
          <Flex align="center" gap="1">
            <Text as="label" weight="bold" size="2">
              Private Enterprise Number (PEN) — Optional
            </Text>
            <InfoPopover title="Private Enterprise Number (PEN)">
              A PEN is a numeric identifier IANA assigns to an organisation. CSIP-Aus requires
              clients to encode a PEN in various requests, and CACTUS now embeds it in every issued
              certificate (as the hardware-module <em>hwType</em> OID). Leave blank to use the
              reserved value <strong>0</strong>. Obtain one for free from{' '}
              <Link href="https://www.iana.org/assignments/enterprise-numbers/" target="_blank">
                IANA
              </Link>
              .
            </InfoPopover>
          </Flex>
          <Flex gap="2" align="center">
            <TextField.Root
              type="number"
              min={1}
              max={4294967295}
              value={penValue}
              onChange={(e) => setPenValue(e.target.value)}
              placeholder="e.g. 123456"
              style={{ flex: 1 }}
            />
            <Button loading={penMutation.isPending} onClick={() => penMutation.mutate()}>
              <IconPencil size={14} />
              Save PEN
            </Button>
          </Flex>
        </Flex>

        <Flex direction="column" gap="2">
          <Flex align="center" gap="1">
            <Text as="label" weight="bold" size="2">
              Notification Domain — Optional (required for aggregator certificates)
            </Text>
            <InfoPopover title="Notification Domain">
              The fully-qualified domain of your webhook endpoint. The utility server (envoy) uses it
              to send subscription notifications back to you over mutual TLS, so it is baked into the
              SAN of any <strong>aggregator</strong> certificate you generate and is checked when
              notifications are delivered. Device certificates do not use it. All subscription
              notification URIs must use this registered domain or they will be rejected.
            </InfoPopover>
          </Flex>
          <Flex gap="2" align="center">
            <TextField.Root
              value={domainValue}
              onChange={(e) => setDomainValue(e.target.value)}
              placeholder="e.g. my.example.com"
              style={{ flex: 1 }}
            />
            <Button loading={domainMutation.isPending} onClick={() => domainMutation.mutate()}>
              <IconPencil size={14} />
              Save Domain
            </Button>
          </Flex>
        </Flex>
      </Flex>
    </SectionCard>
  );
}
