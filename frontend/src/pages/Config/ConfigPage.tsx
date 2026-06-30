import { Callout, Flex, Link, Separator, Skeleton, Text } from '@radix-ui/themes';
import { IconInfoCircle } from '@tabler/icons-react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Link as RouterLink } from 'react-router-dom';
import { fetchConfig } from '../../api/config';
import { Banner } from '../../components/Banner';
import { ErrorAlert } from '../../components/ErrorAlert';
import { PageHeader } from '../../components/PageHeader';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import { useSession } from '../../hooks/useSession';
import { IdentityCard } from './IdentityCard';
import { RunGroupsCard } from './RunGroupsCard';
import { UtilityServerCertCard } from './UtilityServerCertCard';

// After a cert form submission (which downloads a file via hidden iframe), wait briefly
// then refetch so the run group list reflects any cert changes.
const CERT_RELOAD_DELAY_MS = 1500;

export function ConfigPage() {
  useDocumentTitle('Certificates - CACTUS');
  const { data: session } = useSession();
  const queryClient = useQueryClient();
  const [actionError, setActionError] = useState<string | null>(null);

  const configQuery = useQuery({ queryKey: ['config'], queryFn: fetchConfig });
  const config = configQuery.data;
  const runGroups = config?.run_groups ?? [];
  const csipVersions = config?.csip_aus_versions ?? [];
  const hasDomain = !!config?.config.subscription_domain;

  const handleCertAction = () => {
    setTimeout(
      () => void queryClient.invalidateQueries({ queryKey: ['config'] }),
      CERT_RELOAD_DELAY_MS,
    );
  };

  return (
    <Flex direction="column" gap="3">
      <Banner message={session?.banner_message} />
      <PageHeader title="Certificates & Configuration" />
      <Text>
        Set up the identity and certificates used by all future{' '}
        <Link asChild>
          <RouterLink to="/runs">Runs</RouterLink>
        </Link>
        .
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
            <Callout.Root role="status">
              <Callout.Icon>
                <IconInfoCircle size={16} />
              </Callout.Icon>
              <Callout.Text>
                <strong>Getting started:</strong> 1. set your organisation identity (PEN and, for
                aggregators, a notification domain). 2. create a run group for the device or client
                you&apos;re certifying. 3. generate a device or aggregator certificate for it. 4. if
                you receive subscription notifications, download the utility-server certificates so
                your webhook can trust them. Use the (i) icons for more detail on each step.
              </Callout.Text>
            </Callout.Root>
          )}

          <IdentityCard
            pen={config?.config.pen ?? null}
            domain={config?.config.subscription_domain ?? ''}
            setError={setActionError}
          />

          <RunGroupsCard
            runGroups={runGroups}
            csipVersions={csipVersions}
            hasDomain={hasDomain}
            onCertAction={handleCertAction}
            setError={setActionError}
          />

          <UtilityServerCertCard />
        </Flex>
      )}
    </Flex>
  );
}
