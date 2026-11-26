import { Button, Checkbox, Flex, RadioGroup, Text, TextField } from '@radix-ui/themes';
import { IconPlus } from '@tabler/icons-react';
import { useMutation } from '@tanstack/react-query';
import { useState, type ReactNode } from 'react';

import { createCertificate, type CertificateType } from '../api/config';
import type { RunGroupResponse } from '../api/types';
import { InfoPopover } from './InfoPopover';
import { ModalButton } from './ModalButton';

export interface NewCertificateModalProps {
  runGroups: RunGroupResponse[];
  hasDomain: boolean;
  // Run groups ticked for assignment when the modal opens (eg the row the modal was opened from).
  defaultRunGroupIds?: number[];
  trigger: (open: () => void) => ReactNode;
  // Called once the certificate has been generated (and its download started).
  onCreated: (message: string) => void;
  onError: (message: string) => void;
}

// Generates a brand new certificate and (optionally) assigns it to any number of run groups in
// one step. Picking several run groups is how a single certificate gets shared between them.
export function NewCertificateModal({
  runGroups,
  hasDomain,
  defaultRunGroupIds = [],
  trigger,
  onCreated,
  onError,
}: NewCertificateModalProps) {
  return (
    <ModalButton title="Generate a New Certificate" size="lg" trigger={trigger}>
      {(close) => (
        <NewCertificateForm
          runGroups={runGroups}
          hasDomain={hasDomain}
          defaultRunGroupIds={defaultRunGroupIds}
          close={close}
          onCreated={onCreated}
          onError={onError}
        />
      )}
    </ModalButton>
  );
}

// Lives inside the dialog body so the form resets every time the dialog is reopened.
function NewCertificateForm({
  runGroups,
  hasDomain,
  defaultRunGroupIds,
  close,
  onCreated,
  onError,
}: {
  runGroups: RunGroupResponse[];
  hasDomain: boolean;
  defaultRunGroupIds: number[];
  close: () => void;
  onCreated: (message: string) => void;
  onError: (message: string) => void;
}) {
  const [name, setName] = useState('');
  const [type, setType] = useState<CertificateType>('device');
  const [selected, setSelected] = useState<Set<number>>(new Set(defaultRunGroupIds));

  const mutation = useMutation({
    mutationFn: () => createCertificate(name.trim(), type, [...selected]),
  });

  const toggle = (runGroupId: number, checked: boolean) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (checked) next.add(runGroupId);
      else next.delete(runGroupId);
      return next;
    });

  const handleSubmit = () => {
    mutation.mutate(undefined, {
      onSuccess: ({ unassignedRunGroupIds }) => {
        close();
        onCreated(
          `Certificate "${name.trim()}" generated — your download should begin automatically. ` +
            'Keep it safe: the ZIP contains the private key, which cannot be downloaded again.'
        );
        if (unassignedRunGroupIds.length > 0) {
          const names = runGroups
            .filter((rg) => unassignedRunGroupIds.includes(rg.run_group_id))
            .map((rg) => rg.name);
          onError(
            `The certificate was generated but could not be assigned to: ${names.join(', ')}. ` +
              'Assign it from the run groups table instead.'
          );
        }
      },
      onError: (err) => {
        close();
        onError(err.message);
      },
    });
  };

  const canSubmit = name.trim() !== '' && (type === 'device' || hasDomain);

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        if (canSubmit) handleSubmit();
      }}
    >
      <Flex direction="column" gap="4">
        <Text as="label" size="2" weight="bold">
          Name
          <TextField.Root
            autoFocus
            mt="1"
            placeholder="e.g. Battery Mk1 device"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </Text>

        <Flex direction="column" gap="2">
          <Flex align="center" gap="2">
            <Text size="2" weight="bold" id="new-cert-type-label">
              Type
            </Text>
            <InfoPopover title="Device vs Aggregator certificates">
              <strong>Device</strong> certificates identify a single piece of equipment (e.g. a
              battery or meter) and sit on the device signing chain. <strong>Aggregator</strong>{' '}
              certificates identify an organisation acting on behalf of many devices; they sit on
              the aggregator chain and embed your notification domain in the SAN, so the utility
              server can deliver subscription notifications back to you. Both chain to the same root
              that the utility server trusts.
            </InfoPopover>
          </Flex>
          <RadioGroup.Root
            aria-labelledby="new-cert-type-label"
            value={type}
            onValueChange={(v) => setType(v as CertificateType)}
          >
            <RadioGroup.Item value="device">Device</RadioGroup.Item>
            <RadioGroup.Item value="aggregator" disabled={!hasDomain}>
              Aggregator
              {!hasDomain && (
                <Text size="1" color="gray">
                  {' '}
                  — set a notification domain first; an aggregator certificate requires it
                </Text>
              )}
            </RadioGroup.Item>
          </RadioGroup.Root>
        </Flex>

        {runGroups.length > 0 && (
          <Flex direction="column" gap="2">
            <Text size="2" weight="bold">
              Assign to run groups <Text color="gray">(optional)</Text>
            </Text>
            <Text size="1" color="gray">
              Selecting several run groups shares this certificate between them. Any certificate
              they currently use will be replaced (for future runs only).
            </Text>
            {runGroups.map((rg) => (
              <Text as="label" size="2" key={rg.run_group_id}>
                <Flex gap="2" align="center">
                  <Checkbox
                    checked={selected.has(rg.run_group_id)}
                    onCheckedChange={(checked) => toggle(rg.run_group_id, checked === true)}
                  />
                  {rg.name}
                  {rg.certificate_name && (
                    <Text color="gray">(currently {rg.certificate_name})</Text>
                  )}
                </Flex>
              </Text>
            ))}
          </Flex>
        )}

        <Flex justify="end" gap="2">
          <Button type="button" variant="soft" color="gray" onClick={close}>
            Cancel
          </Button>
          <Button type="submit" disabled={!canSubmit} loading={mutation.isPending}>
            <IconPlus size={14} />
            Generate &amp; Download
          </Button>
        </Flex>
      </Flex>
    </form>
  );
}
