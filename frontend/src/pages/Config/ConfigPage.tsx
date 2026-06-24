import { Alert, Divider, SimpleGrid, Skeleton, Stack, Text } from '@mantine/core';
import { useDocumentTitle } from '@mantine/hooks';
import { IconAlertTriangle } from '@tabler/icons-react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { fetchConfig } from '../../api/config';
import { Banner } from '../../components/Banner';
import { ErrorAlert } from '../../components/ErrorAlert';
import { PageHeader } from '../../components/PageHeader';
import { useSession } from '../../hooks/useSession';
import { DeviceCapabilityCard } from './DeviceCapabilityCard';
import { DomainCard } from './DomainCard';
import { PenCard } from './PenCard';
import { RunGroupsCard } from './RunGroupsCard';

// After a cert form submission (which downloads a file via hidden iframe), wait briefly
// then refetch so the run group list reflects any cert changes.
const CERT_RELOAD_DELAY_MS = 1500;

export function ConfigPage() {
  useDocumentTitle('Certificate - CACTUS');
  const { data: session } = useSession();
  const queryClient = useQueryClient();
  const [actionError, setActionError] = useState<string | null>(null);

  const configQuery = useQuery({ queryKey: ['config'], queryFn: fetchConfig });
  const config = configQuery.data;
  const runGroups = config?.run_groups ?? [];
  const csipVersions = config?.csip_aus_versions ?? [];

  const handleCertAction = () => {
    setTimeout(
      () => void queryClient.invalidateQueries({ queryKey: ['config'] }),
      CERT_RELOAD_DELAY_MS,
    );
  };

  return (
    <Stack gap="md">
      <Banner message={session?.banner_message} />
      <PageHeader title="User Configuration" />
      <Text>
        The following configuration options will apply to all future{' '}
        <Text component={Link} to="/runs" c="blue" inherit>
          Runs
        </Text>{' '}
        that are created.
      </Text>
      <Divider />

      {actionError && <ErrorAlert message={actionError} />}

      {configQuery.isPending ? (
        <Stack>
          <Skeleton height={200} />
          <Skeleton height={200} />
        </Stack>
      ) : configQuery.error ? (
        <ErrorAlert message="Unable to communicate with test server. Please try refreshing the page or re-logging in." />
      ) : (
        <Stack gap="md">
          {runGroups.length === 0 && (
            <Alert color="red" icon={<IconAlertTriangle size={16} />} role="alert">
              There are no Run Groups configured. Please create one below in order to start testing.
            </Alert>
          )}

          <RunGroupsCard
            runGroups={runGroups}
            csipVersions={csipVersions}
            onCertAction={handleCertAction}
            setError={setActionError}
          />

          <SimpleGrid cols={3}>
            <PenCard pen={config?.config.pen ?? null} setError={setActionError} />
            <DomainCard
              domain={config?.config.subscription_domain ?? ''}
              setError={setActionError}
            />
            <DeviceCapabilityCard />
          </SimpleGrid>
        </Stack>
      )}
    </Stack>
  );
}
