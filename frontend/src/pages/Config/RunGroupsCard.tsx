import {
  Badge,
  Button,
  Code,
  Flex,
  IconButton,
  Link,
  Table,
  Text,
  TextField,
  Tooltip,
} from '@radix-ui/themes';
import { IconPencil, IconPlus, IconX } from '@tabler/icons-react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useRef, useState } from 'react';
import { Link as RouterLink } from 'react-router-dom';
import { createRunGroup, deleteRunGroup, updateRunGroupName } from '../../api/config';
import type { CSIPAusVersionResponse, RunGroupResponse } from '../../api/types';
import { CopyButton } from '../../components/CopyButton';
import { InfoPopover } from '../../components/InfoPopover';
import { SectionCard } from '../../components/SectionCard';
import { formatRelativeDate } from '../../utils/dates';
import { CertModal } from './CertModal';
import { DeleteModal } from './DeleteModal';
import { SharedCertButton } from './SharedCertButton';

function CertStatusBadge({ runGroup }: { runGroup: RunGroupResponse }) {
  const hasCert = !!(runGroup.certificate_id && runGroup.certificate_created_at);

  if (!hasCert) {
    return (
      <Flex direction="column" gap="1">
        <Badge color="amber">No certificate</Badge>
        <Text size="1" color="gray">
          required before running tests
        </Text>
      </Flex>
    );
  }

  const certType = runGroup.is_device_cert ? 'Device' : 'Aggregator';
  const issued = new Date(runGroup.certificate_created_at as string);

  return (
    <Tooltip content={formatRelativeDate(issued)}>
      <Badge color="green">
        {certType} cert · issued {issued.toLocaleDateString('sv')}
      </Badge>
    </Tooltip>
  );
}

export function RunGroupsCard({
  runGroups,
  csipVersions,
  hasDomain,
  onCertAction,
  setError,
}: {
  runGroups: RunGroupResponse[];
  csipVersions: CSIPAusVersionResponse[];
  hasDomain: boolean;
  onCertAction: (message: string) => void;
  setError: (msg: string | null) => void;
}) {
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState<{ id: number; draft: string } | null>(null);
  const pendingDeleteRef = useRef<number | null>(null);

  // Returning the invalidation promise keeps each mutation pending (spinners showing) until the
  // refetched config lands, so the UI never flashes stale data between save and refetch.
  const onSuccess = () => {
    setError(null);
    return queryClient.invalidateQueries({ queryKey: ['config'] });
  };
  const onError = (err: Error) => setError(err.message);

  const createGroupMutation = useMutation({
    mutationFn: (version: string) => createRunGroup(version),
    onSuccess,
    onError,
  });
  const updateNameMutation = useMutation({
    mutationFn: ({ id, name }: { id: number; name: string }) => updateRunGroupName(id, name),
    onSuccess,
    onError,
  });
  const deleteMutation = useMutation({
    mutationFn: (id: number) => deleteRunGroup(id),
    onSuccess,
    onError,
  });

  return (
    <SectionCard title="Run Groups">
      <Text as="p" mb="1">
        Each run group represents progress towards certification for a single device / client, and
        holds the certificate used by its test runs.
      </Text>
      <Text as="p" mb="3" color="gray">
        Certificates are signed by the CACTUS certificate authority. A run group can use a device or
        aggregator certificate; use the button below to share one aggregator identity across all
        groups.
      </Text>

      {runGroups.length > 0 && (
        <Flex gap="2" align="center" mb="3">
          <SharedCertButton hasDomain={hasDomain} onCertAction={onCertAction} />
        </Flex>
      )}

      {runGroups.length === 0 ? (
        <Text color="gray">No run groups yet — create your first one below to start testing.</Text>
      ) : (
        <Table.Root variant="surface">
          <Table.Header>
            <Table.Row>
              <Table.ColumnHeaderCell>Certificate</Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell>Name</Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell>Version</Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell>
                <Flex align="center" gap="1">
                  DeviceCapability URI
                  <InfoPopover title="DeviceCapability URI">
                    Each run group has a single, fixed DeviceCapability URI shared across all of its
                    test runs. Because the URI is fixed per group, only one test run can be active
                    in a group at a time, and the URI only responds once a run has been started from
                    the Runs page.
                  </InfoPopover>
                </Flex>
              </Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell>Runs</Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell />
            </Table.Row>
          </Table.Header>
          <Table.Body>
            {runGroups.map((rg) => (
              <Table.Row key={rg.run_group_id}>
                <Table.Cell>
                  <Flex direction="column" gap="2" align="start">
                    <CertStatusBadge runGroup={rg} />
                    <CertModal runGroup={rg} hasDomain={hasDomain} onCertAction={onCertAction} />
                  </Flex>
                </Table.Cell>
                <Table.Cell>
                  {editing?.id === rg.run_group_id ? (
                    <form
                      onSubmit={(e) => {
                        e.preventDefault();
                        const name = editing.draft.trim();
                        if (name && name !== rg.name) {
                          updateNameMutation.mutate(
                            { id: rg.run_group_id, name },
                            { onSuccess: () => setEditing(null) }
                          );
                        }
                      }}
                    >
                      <Flex gap="2" align="center">
                        <TextField.Root
                          autoFocus
                          value={editing.draft}
                          onChange={(e) =>
                            setEditing({ id: rg.run_group_id, draft: e.target.value })
                          }
                          onKeyDown={(e) => {
                            if (e.key === 'Escape') setEditing(null);
                          }}
                          style={{ flex: 1 }}
                        />
                        <Button
                          type="submit"
                          variant="outline"
                          disabled={editing.draft.trim() === '' || editing.draft.trim() === rg.name}
                          loading={
                            updateNameMutation.isPending &&
                            updateNameMutation.variables?.id === rg.run_group_id
                          }
                        >
                          Save
                        </Button>
                        <IconButton
                          type="button"
                          variant="ghost"
                          color="gray"
                          onClick={() => setEditing(null)}
                          aria-label="Cancel"
                        >
                          <IconX size={14} />
                        </IconButton>
                      </Flex>
                    </form>
                  ) : (
                    <Flex gap="2" align="center">
                      <Text>{rg.name}</Text>
                      <IconButton
                        type="button"
                        variant="ghost"
                        color="gray"
                        onClick={() => setEditing({ id: rg.run_group_id, draft: rg.name })}
                        aria-label="Rename"
                      >
                        <IconPencil size={14} />
                      </IconButton>
                    </Flex>
                  )}
                </Table.Cell>
                <Table.Cell>
                  <Code>{rg.csip_aus_version}</Code>
                </Table.Cell>
                <Table.Cell>
                  {rg.static_uri ? (
                    <Flex align="center" gap="1">
                      <Code size="1" style={{ wordBreak: 'break-all' }}>
                        {rg.static_uri}
                      </Code>
                      <CopyButton value={rg.static_uri} />
                    </Flex>
                  ) : (
                    <Text size="1" color="gray">
                      —
                    </Text>
                  )}
                </Table.Cell>
                <Table.Cell>
                  <Link asChild>
                    <RouterLink to={`/group/${rg.run_group_id}/runs`}>
                      {rg.total_runs} {rg.total_runs === 1 ? 'run' : 'runs'}
                    </RouterLink>
                  </Link>
                </Table.Cell>
                <Table.Cell>
                  <DeleteModal
                    runGroup={rg}
                    isDeleting={
                      deleteMutation.isPending && pendingDeleteRef.current === rg.run_group_id
                    }
                    onDelete={() => {
                      pendingDeleteRef.current = rg.run_group_id;
                      deleteMutation.mutate(rg.run_group_id);
                    }}
                  />
                </Table.Cell>
              </Table.Row>
            ))}
          </Table.Body>
        </Table.Root>
      )}

      <Flex gap="2" align="center" mt="3">
        {csipVersions.map((v) => (
          <Button
            key={v.version}
            variant="outline"
            loading={createGroupMutation.isPending && createGroupMutation.variables === v.version}
            onClick={() => createGroupMutation.mutate(v.version)}
          >
            <IconPlus size={14} />
            New {v.version} Group
          </Button>
        ))}
      </Flex>
    </SectionCard>
  );
}
