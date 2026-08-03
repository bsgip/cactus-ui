import { Box, Flex, Link, Skeleton, Text } from '@radix-ui/themes';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef, useState } from 'react';
import { Link as RouterLink } from 'react-router-dom';
import { fetchConfig } from '../../api/config';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import { GettingStartedChecklist } from './GettingStartedChecklist';
import { OrganisationCard } from './OrganisationCard';
import { NotificationsCard } from './NotificationsCard';
import { RunGroupsCard } from './RunGroupsCard';
import Page from '../../components/Page';
import { ErrorAlert } from '../../components/ErrorAlert';
import NoticeAlert from '../../components/NoticeAlert';

const NOTICE_AUTO_DISMISS_MS = 6000;

export function ConfigPage() {
  useDocumentTitle('Certificates - CACTUS');
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

    // The cert download has already completed by the time this fires, so the refetched
    // config reflects the new certificate immediately.
    void queryClient.invalidateQueries({ queryKey: ['config'] });
  };


  return (
    <Page title="Certificates & Configuration" includeBanner={true}>
      <Box mb="6">
        <Text>
          Set up the identity and certificates used by all future{' '}
          <Link asChild>
            <RouterLink to="/runs">runs</RouterLink>
          </Link>
          .
        </Text>
      </Box>

      {actionError && <ErrorAlert message={actionError} />}
      {actionNotice && <NoticeAlert message={actionNotice} />}

      {configQuery.isPending ? (
        <Flex direction="column" gap="3">
          <Skeleton height="200px" />
          <Skeleton height="200px" />
        </Flex>
      ) : configQuery.error ? (
        <ErrorAlert message="Unable to communicate with test server. Please try refreshing the page or re-logging in." />
      ) : (
        <Flex direction="column" gap="6">
          <GettingStartedChecklist
            pen={config?.config.pen ?? null}
            domain={config?.config.subscription_domain ?? ''}
            runGroups={runGroups}
          />

          <OrganisationCard
            pen={config?.config.pen ?? null}
            setError={handleActionError}
          />
          <NotificationsCard
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

    </Page>
  );
}
