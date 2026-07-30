import {
  Button,
  Flex,
  Text,
} from '@radix-ui/themes';
import { IconPlus } from '@tabler/icons-react';
import { useMutation, useQueryClient } from '@tanstack/react-query';

import { createRunGroup } from '../../api/config';
import type { CSIPAusVersionResponse, RunGroupResponse } from '../../api/types';
import { SharedCertButton } from './SharedCertButton';
import { Section } from '../../components/Section';
import RunGroupTable from '../../components/RunGroupTable';
import Highlight from '../../components/Highlight';


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
    <Section title="RUN GROUPS & CERTIFICATES">
      <Text as="p" mb="3">
        A run group represents progress towards CSIP-Aus certification for a single device / client.
      </Text>
      <Text as="p" mb="3">
        Each run group has a certificate used to secure communications between the client and utility server during testing.
        These certificates are signed by the CACTUS certificate authority.
      </Text>
      <Text as="p" mb="6">
        A run group can be configured to use either a device or an aggregator certificate.
        Run groups can also be configured to use a single shared aggregator certificate through the <Highlight color="var(--gray-a3)">Set SHARED Aggregator Certificate for ALL groups</Highlight> option below.
      </Text>

      {runGroups.length === 0 ? (
        <Text color="gray">No run groups yet — create your first one below to start testing.</Text>
      ) : (
        <RunGroupTable setError={setError} runGroups={runGroups} hasDomain={hasDomain} onCertAction={onCertAction} />
      )}

      <Flex justify="between" mt="4">
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
        {runGroups.length > 0 && (
          <SharedCertButton
            hasDomain={hasDomain}
            onCertAction={onCertAction}
            onCertError={setError}
          />
        )}
      </Flex>
    </Section>
  );
}

