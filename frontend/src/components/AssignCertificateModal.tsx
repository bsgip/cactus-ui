import { Badge, Button, Flex, RadioGroup, Text } from '@radix-ui/themes';
import { IconArrowsExchange } from '@tabler/icons-react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';

import { assignRunGroupCertificate, unassignRunGroupCertificate } from '../api/config';
import type { CertificateResponse, RunGroupResponse } from '../api/types';
import { certExpiryStatus, certificateLabel } from '../utils/certificates';
import { ModalButton } from './ModalButton';

const NO_CERTIFICATE = 'none';

// Picks which of the user's existing certificates a run group uses (or none). The same
// certificate can be picked for several run groups - that's how certificates are shared.
export function AssignCertificateModal({
  runGroup,
  runGroups,
  certificates,
  onCertAction,
  onCertError,
}: {
  runGroup: RunGroupResponse;
  runGroups: RunGroupResponse[];
  certificates: CertificateResponse[];
  onCertAction: (message: string) => void;
  onCertError: (message: string) => void;
}) {
  return (
    <ModalButton
      title={`Certificate for ${runGroup.name}`}
      size="lg"
      trigger={(open) => (
        <Button variant="outline" size="1" onClick={open}>
          <IconArrowsExchange size={14} />
          Change
        </Button>
      )}
    >
      {(close) => (
        <AssignCertificateForm
          runGroup={runGroup}
          runGroups={runGroups}
          certificates={certificates}
          close={close}
          onCertAction={onCertAction}
          onCertError={onCertError}
        />
      )}
    </ModalButton>
  );
}

function AssignCertificateForm({
  runGroup,
  runGroups,
  certificates,
  close,
  onCertAction,
  onCertError,
}: {
  runGroup: RunGroupResponse;
  runGroups: RunGroupResponse[];
  certificates: CertificateResponse[];
  close: () => void;
  onCertAction: (message: string) => void;
  onCertError: (message: string) => void;
}) {
  const queryClient = useQueryClient();
  const current =
    runGroup.assigned_certificate_id != null
      ? String(runGroup.assigned_certificate_id)
      : NO_CERTIFICATE;
  const [choice, setChoice] = useState(current);

  const runGroupName = (id: number) =>
    runGroups.find((rg) => rg.run_group_id === id)?.name ?? `#${id}`;

  const mutation = useMutation({
    mutationFn: () =>
      choice === NO_CERTIFICATE
        ? unassignRunGroupCertificate(runGroup.run_group_id)
        : assignRunGroupCertificate(runGroup.run_group_id, Number(choice)),
    // Keep the dialog pending until the refetched config lands so nothing flashes stale.
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['config'] }),
  });

  const handleSave = () => {
    mutation.mutate(undefined, {
      onSuccess: () => {
        close();
        const chosen = certificates.find((c) => String(c.certificate_id) === choice);
        onCertAction(
          (chosen
            ? `${runGroup.name} now uses certificate "${chosen.name}".`
            : `${runGroup.name} no longer has a certificate.`) +
            ' Runs already in progress keep the certificate they started with.'
        );
      },
      onError: (err) => {
        close();
        onCertError(err.message);
      },
    });
  };

  return (
    <Flex direction="column" gap="3">
      <Text size="2">
        Choose the certificate that new test runs in <strong>{runGroup.name}</strong> will use. Runs
        already in progress are unaffected.
      </Text>

      <RadioGroup.Root
        aria-label={`Certificate for ${runGroup.name}`}
        value={choice}
        onValueChange={setChoice}
      >
        {certificates.map((cert) => {
          const others = cert.run_group_ids.filter((id) => id !== runGroup.run_group_id);
          const expiry = certExpiryStatus(cert.expires_at);
          return (
            <RadioGroup.Item key={cert.certificate_id} value={String(cert.certificate_id)}>
              <Flex direction="column">
                <Flex gap="2" align="center">
                  <Text>{certificateLabel(cert)}</Text>
                  {expiry === 'expired' && <Badge color="red">Expired</Badge>}
                </Flex>
                {others.length > 0 && (
                  <Text size="1" color="gray">
                    Also used by: {others.map(runGroupName).join(', ')}
                  </Text>
                )}
              </Flex>
            </RadioGroup.Item>
          );
        })}
        <RadioGroup.Item value={NO_CERTIFICATE}>
          <Text color="gray">No certificate (test runs can&apos;t be started)</Text>
        </RadioGroup.Item>
      </RadioGroup.Root>

      <Flex justify="end" gap="2">
        <Button variant="soft" color="gray" onClick={close}>
          Cancel
        </Button>
        <Button disabled={choice === current} loading={mutation.isPending} onClick={handleSave}>
          Save
        </Button>
      </Flex>
    </Flex>
  );
}
