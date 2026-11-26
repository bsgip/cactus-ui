import {
  Button,
  Flex,
  Text,
} from '@radix-ui/themes';
import { IconPlus } from '@tabler/icons-react';
import { useMutation, useQueryClient } from '@tanstack/react-query';

import { createRunGroup } from '../../api/config';
import type {
  CertificateResponse,
  CSIPAusVersionResponse,
  RunGroupResponse,
} from '../../api/types';
import { Section } from '../../components/Section';
import RunGroupConfigTable from '../../components/RunGroupConfigTable';


export function RunGroupsCard({
  runGroups,
  certificates,
  csipVersions,
  hasDomain,
  onCertAction,
  setError,
}: {
  runGroups: RunGroupResponse[];
  certificates: CertificateResponse[];
  csipVersions: CSIPAusVersionResponse[];
  hasDomain: boolean;
  onCertAction: (message: string) => void;
  setError: (msg: string | null) => void;
}) {
  const queryClient = useQueryClient();

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

  return (
    <Section title="RUN GROUPS">
      <Text as="p" mb="3">
        A run group represents progress towards CSIP-Aus certification for a single device / client.
      </Text>
      <Text as="p" mb="6">
        Each run group needs a certificate (device or aggregator) before tests can be run. Pick one of
        your existing certificates with <strong>Change</strong>, or generate a new one with{' '}
        <strong>New</strong>. Changing a run group&apos;s certificate only affects runs started
        afterwards.
      </Text>

      {runGroups.length === 0 ? (
        <Text color="gray">No run groups yet — create your first one below to start testing.</Text>
      ) : (
        <RunGroupConfigTable
          setError={setError}
          runGroups={runGroups}
          certificates={certificates}
          hasDomain={hasDomain}
          onCertAction={onCertAction}
        />
      )}

      <Flex mt="4">
      <Flex gap="2" align="center">
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
      </Flex>
    </Section>
  );
}

