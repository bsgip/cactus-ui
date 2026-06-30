import { Button, Code, Flex, Table, Text, TextField } from '@radix-ui/themes';
import { IconPlus } from '@tabler/icons-react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useRef, useState } from 'react';
import { createRunGroup, deleteRunGroup, updateRunGroupName } from '../../api/config';
import type { CSIPAusVersionResponse, RunGroupResponse } from '../../api/types';
import { InfoPopover } from '../../components/InfoPopover';
import { SectionCard } from '../../components/SectionCard';
import { CertModal } from './CertModal';
import { DeleteModal } from './DeleteModal';
import { SharedCertButton } from './SharedCertButton';

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
  onCertAction: () => void;
  setError: (msg: string | null) => void;
}) {
  const queryClient = useQueryClient();
  const [editNames, setEditNames] = useState<Record<number, string>>({});
  const pendingDeleteRef = useRef<number | null>(null);

  const onSuccess = () => {
    setError(null);
    void queryClient.invalidateQueries({ queryKey: ['config'] });
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
        <Text weight="bold">There doesn&apos;t seem to be anything here...</Text>
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
                    test runs. Because the URI is fixed per group, only one test run can be active in
                    a group at a time, and the URI only responds once a run has been started from the
                    Runs page.
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
                  <CertModal runGroup={rg} hasDomain={hasDomain} onCertAction={onCertAction} />
                </Table.Cell>
                <Table.Cell>
                  <Flex gap="2" align="center">
                    <TextField.Root
                      value={editNames[rg.run_group_id] ?? rg.name}
                      onChange={(e) =>
                        setEditNames((prev) => ({ ...prev, [rg.run_group_id]: e.target.value }))
                      }
                      style={{ flex: 1 }}
                    />
                    <Button
                      variant="outline"
                      loading={
                        updateNameMutation.isPending &&
                        updateNameMutation.variables?.id === rg.run_group_id
                      }
                      onClick={() =>
                        updateNameMutation.mutate({
                          id: rg.run_group_id,
                          name: editNames[rg.run_group_id] ?? rg.name,
                        })
                      }
                    >
                      Save
                    </Button>
                  </Flex>
                </Table.Cell>
                <Table.Cell>
                  <Code>{rg.csip_aus_version}</Code>
                </Table.Cell>
                <Table.Cell>
                  {rg.static_uri ? (
                    <Text size="1" style={{ textDecoration: 'underline', wordBreak: 'break-all' }}>
                      {rg.static_uri}
                    </Text>
                  ) : (
                    <Text size="1" color="gray">
                      —
                    </Text>
                  )}
                </Table.Cell>
                <Table.Cell>{rg.total_runs} total run(s)</Table.Cell>
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
