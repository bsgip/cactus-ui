import { Button, Code, Group, Table, Text, TextInput } from '@mantine/core';
import { IconDownload, IconPlus } from '@tabler/icons-react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useRef, useState } from 'react';
import { createRunGroup, deleteRunGroup, updateRunGroupName } from '../../api/config';
import type { CSIPAusVersionResponse, RunGroupResponse } from '../../api/types';
import { SectionCard } from '../../components/SectionCard';
import { CertModal } from './CertModal';
import { DeleteModal } from './DeleteModal';
import { SharedCertMenu } from './SharedCertMenu';

export function RunGroupsCard({
  runGroups,
  csipVersions,
  onCertAction,
  setError,
}: {
  runGroups: RunGroupResponse[];
  csipVersions: CSIPAusVersionResponse[];
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
      <Text mb="xs">
        Each run group represents progress towards certification for a single device / client.
      </Text>
      <Text mb="sm">All certificates will be signed by the CACTUS certificate authority.</Text>

      <Group mb="md">
        <Button
          component="a"
          href="/config/ca_cert"
          variant="outline"
          leftSection={<IconDownload size={14} />}
        >
          Download SERCA Certificate
        </Button>
        {runGroups.length > 1 && <SharedCertMenu onCertAction={onCertAction} />}
      </Group>

      {runGroups.length === 0 ? (
        <Text fw={700}>There doesn&apos;t seem to be anything here...</Text>
      ) : (
        <Table>
          <Table.Tbody>
            {runGroups.map((rg) => (
              <Table.Tr key={rg.run_group_id}>
                <Table.Td>
                  <CertModal runGroup={rg} onCertAction={onCertAction} />
                </Table.Td>
                <Table.Td>
                  <Group gap="xs">
                    <TextInput
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
                  </Group>
                </Table.Td>
                <Table.Td>
                  <Code>{rg.csip_aus_version}</Code>
                </Table.Td>
                <Table.Td>
                  {rg.static_uri ? (
                    <Text component="u" size="xs">
                      {rg.static_uri}
                    </Text>
                  ) : (
                    <Text size="xs" c="dimmed">
                      URI pending
                    </Text>
                  )}
                </Table.Td>
                <Table.Td>{rg.total_runs} total run(s)</Table.Td>
                <Table.Td>
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
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}

      <Group mt="md">
        {csipVersions.map((v) => (
          <Button
            key={v.version}
            variant="outline"
            leftSection={<IconPlus size={14} />}
            loading={createGroupMutation.isPending && createGroupMutation.variables === v.version}
            onClick={() => createGroupMutation.mutate(v.version)}
          >
            New {v.version} Group
          </Button>
        ))}
      </Group>
    </SectionCard>
  );
}
