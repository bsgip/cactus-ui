import { Flex } from '@radix-ui/themes';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { fetchComplianceRequests } from '../api/compliance';
import { ErrorAlert } from '../components/ErrorAlert';
import { PageHeader } from '../components/PageHeader';
import { PageSpinner } from '../components/PageSpinner';
import { useConfirm } from '../components/useConfirm';
import { useDocumentTitle } from '../hooks/useDocumentTitle';
import NewRequestButton from '../components/NewRequestButton';
import PrefillDialog from '../components/PrefillDialog';
import ComplianceRequestTable from '../components/ComplianceRequestTable';
import type { ComplianceRequestResponse } from '../api/types';


export function CompliancePage() {
  useDocumentTitle('Compliance - CACTUS');
  const queryClient = useQueryClient();
  const { confirm, confirmDialog } = useConfirm();
  const [prefillId, setPrefillId] = useState<string>('none');
  const [actionError, setActionError] = useState<string | null>(null);

  const requestPath = '/compliance-request';
  const queryKey = ['compliance', 'requests'];
  const query = useQuery({
    queryKey,
    queryFn: () => fetchComplianceRequests(),
  });
  const requests: ComplianceRequestResponse[] = query.data?.requests ?? [];
  const refresh = () => void queryClient.invalidateQueries({ queryKey });

  const willPrefill = prefillId !== 'none';
  const target = willPrefill ? `${requestPath}?prefill=${prefillId}` : requestPath;

  return (
    <Flex direction="column" gap="3">
      {confirmDialog}
      <PageHeader title="Compliance" />

      {actionError && <ErrorAlert message={actionError} />}

      <Flex>
        {requests.length === 0 
        ? <NewRequestButton requestPath={requestPath} />
        : <PrefillDialog prefillId={prefillId} setPrefillId={setPrefillId} requests={requests} target={target}/>
        }
      </Flex>


      {query.isPending ? (
        <PageSpinner />
      ) : query.error ? (
        <ErrorAlert message="Failed to fetch compliance requests." />
      ) : (
        <ComplianceRequestTable requests={requests} refresh={refresh} setActionError={setActionError} requestPath={requestPath} confirm={confirm}/>
      )}
    </Flex>
  );
}

