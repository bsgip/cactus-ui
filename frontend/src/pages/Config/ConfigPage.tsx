import { Callout, Flex, Grid, Link, Separator, Skeleton, Text } from '@radix-ui/themes';
import { IconAlertTriangle } from '@tabler/icons-react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Link as RouterLink } from 'react-router-dom';
import { fetchConfig } from '../../api/config';
import { Banner } from '../../components/Banner';
import { ErrorAlert } from '../../components/ErrorAlert';
import { PageHeader } from '../../components/PageHeader';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
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
    <Flex direction="column" gap="3">
      <Banner message={session?.banner_message} />
      <PageHeader title="User Configuration" />
      <Text>
        The following configuration options will apply to all future{' '}
        <Link asChild>
          <RouterLink to="/runs">Runs</RouterLink>
        </Link>{' '}
        that are created.
      </Text>
      <Separator size="4" />

      {actionError && <ErrorAlert message={actionError} />}

      {configQuery.isPending ? (
        <Flex direction="column" gap="3">
          <Skeleton height="200px" />
          <Skeleton height="200px" />
        </Flex>
      ) : configQuery.error ? (
        <ErrorAlert message="Unable to communicate with test server. Please try refreshing the page or re-logging in." />
      ) : (
        <Flex direction="column" gap="3">
          {runGroups.length === 0 && (
            <Callout.Root color="red" role="alert">
              <Callout.Icon>
                <IconAlertTriangle size={16} />
              </Callout.Icon>
              <Callout.Text>
                There are no Run Groups configured. Please create one below in order to start
                testing.
              </Callout.Text>
            </Callout.Root>
          )}

          <RunGroupsCard
            runGroups={runGroups}
            csipVersions={csipVersions}
            onCertAction={handleCertAction}
            setError={setActionError}
          />

          <Grid columns="3" gap="3">
            <PenCard pen={config?.config.pen ?? null} setError={setActionError} />
            <DomainCard
              domain={config?.config.subscription_domain ?? ''}
              setError={setActionError}
            />
            <DeviceCapabilityCard />
          </Grid>
        </Flex>
      )}
    </Flex>
  );
}
