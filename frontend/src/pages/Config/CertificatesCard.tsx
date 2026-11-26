import { Badge, Button, Flex, IconButton, Table, Text, Tooltip } from '@radix-ui/themes';
import { IconDownload, IconPlus, IconRecycle, IconTrash } from '@tabler/icons-react';
import { useMutation, useQueryClient } from '@tanstack/react-query';

import { certificateDownloadUrl, deleteCertificate, regenerateCertificate } from '../../api/config';
import type { CertificateResponse, RunGroupResponse } from '../../api/types';
import { NewCertificateModal } from '../../components/NewCertificateModal';
import { Section } from '../../components/Section';
import { useConfirm } from '../../components/useConfirm';
import { formatRelativeDate } from '../../utils/dates';
import { certExpiryStatus, certTypeLabel, formatCertDate } from '../../utils/certificates';

function ExpiryCell({ cert }: { cert: CertificateResponse }) {
  const status = certExpiryStatus(cert.expires_at);
  const date = formatCertDate(cert.expires_at);
  return (
    <Table.Cell>
      <Tooltip content={formatRelativeDate(new Date(cert.expires_at))}>
        {status === 'expired' ? (
          <Badge color="red">Expired {date}</Badge>
        ) : status === 'expiring' ? (
          <Badge color="amber">Expires {date}</Badge>
        ) : (
          <Text>{date}</Text>
        )}
      </Tooltip>
    </Table.Cell>
  );
}

function AssignedRunGroupsCell({
  cert,
  runGroupsById,
}: {
  cert: CertificateResponse;
  runGroupsById: Map<number, RunGroupResponse>;
}) {
  return (
    <Table.Cell>
      {cert.run_group_ids.length === 0 ? (
        <Text size="2" color="gray">
          Not assigned
        </Text>
      ) : (
        <Flex gap="1" wrap="wrap">
          {cert.run_group_ids.map((id) => (
            <Badge key={id} color="gray" variant="soft">
              {runGroupsById.get(id)?.name ?? `Run group #${id}`}
            </Badge>
          ))}
        </Flex>
      )}
    </Table.Cell>
  );
}

export function CertificatesCard({
  certificates,
  runGroups,
  hasDomain,
  onCertAction,
  setError,
}: {
  certificates: CertificateResponse[];
  runGroups: RunGroupResponse[];
  hasDomain: boolean;
  onCertAction: (message: string) => void;
  setError: (msg: string | null) => void;
}) {
  const queryClient = useQueryClient();
  const { confirm, confirmDialog } = useConfirm();
  const runGroupsById = new Map(runGroups.map((rg) => [rg.run_group_id, rg]));
  const groupNames = (cert: CertificateResponse) =>
    cert.run_group_ids.map((id) => runGroupsById.get(id)?.name ?? `#${id}`).join(', ');

  // Returning the invalidation promise keeps each mutation pending until the refetch lands.
  const refetch = () => queryClient.invalidateQueries({ queryKey: ['config'] });

  const regenerateMutation = useMutation({
    mutationFn: (cert: CertificateResponse) => regenerateCertificate(cert.certificate_id),
    onSuccess: (_, cert) => {
      onCertAction(
        `Certificate "${cert.name}" regenerated — your download should begin automatically.`
      );
      return refetch();
    },
    onError: (err: Error) => setError(err.message),
  });

  const deleteMutation = useMutation({
    mutationFn: (cert: CertificateResponse) => deleteCertificate(cert.certificate_id),
    onSuccess: (_, cert) => {
      onCertAction(`Certificate "${cert.name}" deleted.`);
      return refetch();
    },
    onError: (err: Error) => setError(err.message),
  });

  const confirmRegenerate = (cert: CertificateResponse) =>
    confirm({
      title: `Regenerate ${cert.name}?`,
      body: (
        <>
          This generates and downloads a brand-new certificate, and the current one stops working
          immediately.{' '}
          {cert.run_group_ids.length > 0
            ? `Every device or client using it (${groupNames(cert)}) must switch to the new one.`
            : 'It is not assigned to any run groups.'}
        </>
      ),
      confirmLabel: 'Regenerate & Download',
      confirmColor: 'red',
      onConfirm: () => regenerateMutation.mutate(cert),
    });

  const confirmDelete = (cert: CertificateResponse) =>
    confirm({
      title: `Delete ${cert.name}?`,
      body: (
        <>
          This permanently deletes the certificate.{' '}
          {cert.run_group_ids.length > 0
            ? `${groupNames(cert)} will be left without a certificate until another is assigned.`
            : 'It is not assigned to any run groups.'}{' '}
          Results of past runs are kept. Certificates in use by active runs cannot be deleted.
        </>
      ),
      confirmLabel: 'Delete',
      confirmColor: 'red',
      onConfirm: () => deleteMutation.mutate(cert),
    });

  return (
    <Section title="CERTIFICATES">
      {confirmDialog}
      <Text as="p" mb="3">
        Certificates secure communications between your client and the utility server during
        testing. They are signed by the CACTUS certificate authority.
      </Text>
      <Text as="p" mb="6">
        Each run group uses one certificate. A certificate can be shared by several run groups -
        e.g. one aggregator certificate for your whole organisation.
      </Text>

      {certificates.length === 0 ? (
        <Text color="gray">No certificates yet — generate one below.</Text>
      ) : (
        <Table.Root variant="surface">
          <Table.Header>
            <Table.Row>
              <Table.ColumnHeaderCell>Name</Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell>Type</Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell>Issued</Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell>Expires</Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell>Used by run groups</Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell />
            </Table.Row>
          </Table.Header>
          <Table.Body>
            {certificates.map((cert) => (
              <Table.Row key={cert.certificate_id}>
                <Table.Cell>
                  <Text weight="medium">{cert.name}</Text>
                </Table.Cell>
                <Table.Cell>
                  <Badge color={cert.is_device_cert ? 'blue' : 'purple'}>
                    {certTypeLabel(cert.is_device_cert)}
                  </Badge>
                </Table.Cell>
                <Table.Cell>
                  <Tooltip content={formatRelativeDate(new Date(cert.generated_at))}>
                    <Text>{formatCertDate(cert.generated_at)}</Text>
                  </Tooltip>
                </Table.Cell>
                <ExpiryCell cert={cert} />
                <AssignedRunGroupsCell cert={cert} runGroupsById={runGroupsById} />
                <Table.Cell>
                  <Flex gap="2" justify="end">
                    <Tooltip content="Download certificate (PEM, incl. CA chain)">
                      <IconButton asChild variant="outline" aria-label={`Download ${cert.name}`}>
                        <a href={certificateDownloadUrl(cert.certificate_id)}>
                          <IconDownload size={14} />
                        </a>
                      </IconButton>
                    </Tooltip>
                    <Tooltip content="Regenerate certificate">
                      <IconButton
                        variant="outline"
                        color="orange"
                        aria-label={`Regenerate ${cert.name}`}
                        loading={
                          regenerateMutation.isPending &&
                          regenerateMutation.variables?.certificate_id === cert.certificate_id
                        }
                        onClick={() => confirmRegenerate(cert)}
                      >
                        <IconRecycle size={14} />
                      </IconButton>
                    </Tooltip>
                    <Tooltip content="Delete certificate">
                      <IconButton
                        variant="outline"
                        color="red"
                        aria-label={`Delete ${cert.name}`}
                        loading={
                          deleteMutation.isPending &&
                          deleteMutation.variables?.certificate_id === cert.certificate_id
                        }
                        onClick={() => confirmDelete(cert)}
                      >
                        <IconTrash size={14} />
                      </IconButton>
                    </Tooltip>
                  </Flex>
                </Table.Cell>
              </Table.Row>
            ))}
          </Table.Body>
        </Table.Root>
      )}

      <Flex mt="4">
        <NewCertificateModal
          runGroups={runGroups}
          hasDomain={hasDomain}
          onCreated={onCertAction}
          onError={setError}
          trigger={(open) => (
            <Button variant="outline" onClick={open}>
              <IconPlus size={14} />
              New Certificate
            </Button>
          )}
        />
      </Flex>
    </Section>
  );
}
