import { Callout, Flex, Link, Separator, Skeleton, Text } from '@radix-ui/themes';
import { IconCircleCheck } from '@tabler/icons-react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef, useState } from 'react';
import { Link as RouterLink } from 'react-router-dom';
import { fetchConfig } from '../../api/config';
import { Banner } from '../../components/Banner';
import { ErrorAlert } from '../../components/ErrorAlert';
import { PageHeader } from '../../components/PageHeader';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import { useSession } from '../../hooks/useSession';
import { GettingStartedChecklist } from './GettingStartedChecklist';
import { OrganisationCard } from './OrganisationCard';
import { RunGroupsCard } from './RunGroupsCard';

// After a cert form submission (which downloads a file via hidden iframe), wait briefly
// then refetch so the run group list reflects any cert changes.
const CERT_RELOAD_DELAY_MS = 1500;
const NOTICE_AUTO_DISMISS_MS = 6000;

export function ConfigPage() {
  useDocumentTitle('Certificates - CACTUS');
  const { data: session } = useSession();
  const queryClient = useQueryClient();
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);
  const noticeTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(
    () => () => {
      if (noticeTimeoutRef.current) clearTimeout(noticeTimeoutRef.current);
    },
    []
  );

  const configQuery = useQuery({ queryKey: ['config'], queryFn: fetchConfig });
  const config = configQuery.data;
  const runGroups = config?.run_groups ?? [];
  const csipVersions = config?.csip_aus_versions ?? [];
  const hasDomain = !!config?.config.subscription_domain;

  const handleActionError = (message: string | null) => {
    setActionError(message);
    if (message) {
      setActionNotice(null);
      if (noticeTimeoutRef.current) clearTimeout(noticeTimeoutRef.current);
    }
  };

  const handleCertAction = (message: string) => {
    setActionError(null);
    setActionNotice(message);
    if (noticeTimeoutRef.current) clearTimeout(noticeTimeoutRef.current);
    noticeTimeoutRef.current = setTimeout(() => setActionNotice(null), NOTICE_AUTO_DISMISS_MS);

    setTimeout(
      () => void queryClient.invalidateQueries({ queryKey: ['config'] }),
      CERT_RELOAD_DELAY_MS
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
      {actionNotice && (
        <Callout.Root color="green" role="status" mb="3">
          <Callout.Icon>
            <IconCircleCheck size={16} />
          </Callout.Icon>
          <Callout.Text>{actionNotice}</Callout.Text>
        </Callout.Root>
      )}

      {configQuery.isPending ? (
        <Flex direction="column" gap="3">
          <Skeleton height="200px" />
          <Skeleton height="200px" />
        </Flex>
      ) : configQuery.error ? (
        <ErrorAlert message="Unable to communicate with test server. Please try refreshing the page or re-logging in." />
      ) : (
        <Flex direction="column" gap="3">
          <GettingStartedChecklist
            pen={config?.config.pen ?? null}
            domain={config?.config.subscription_domain ?? ''}
            runGroups={runGroups}
          />

          <OrganisationCard
            pen={config?.config.pen ?? null}
            domain={config?.config.subscription_domain ?? ''}
            setError={handleActionError}
          />

          <RunGroupsCard
            runGroups={runGroups}
            csipVersions={csipVersions}
            hasDomain={hasDomain}
            onCertAction={handleCertAction}
            setError={handleActionError}
          />
        </Flex>
      )}
    </Flex>
  );
}
