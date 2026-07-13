import {
  Flex,
  TextField,
} from '@radix-ui/themes';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import {
  fetchAdminComplianceRequests,
  fetchComplianceRequests,
} from '../api/compliance';
import { ErrorAlert } from '../components/ErrorAlert';
import { PageHeader } from '../components/PageHeader';
import { PageSpinner } from '../components/PageSpinner';
import { useConfirm } from '../components/useConfirm';
import { useDocumentTitle } from '../hooks/useDocumentTitle';
import NewRequestButton from '../components/NewRequestButton';
import PrefillDialog from '../components/PrefillDialog';
import ComplianceRequestTable from '../components/ComplianceRequestTable';
import type { AdminComplianceRequestResponse, ComplianceRequestResponse } from '../api/types';
type AnyRequest = ComplianceRequestResponse | AdminComplianceRequestResponse;



// One component for both views: isAdminView selects the admin endpoints, columns, status
// wording, and the per-status action set.
export function CompliancePage({ isAdminView }: { isAdminView: boolean }) {
  useDocumentTitle('Compliance - CACTUS');
  const queryClient = useQueryClient();
  const { confirm, confirmDialog } = useConfirm();
  const [filter, setFilter] = useState('');
  const [prefillId, setPrefillId] = useState<string>('none');
  const [actionError, setActionError] = useState<string | null>(null);

  const requestPath = isAdminView ? '/admin/compliance-request' : '/compliance-request';
  const queryKey = ['compliance', 'requests', isAdminView];
  const query = useQuery({
    queryKey,
    queryFn: () => (isAdminView ? fetchAdminComplianceRequests() : fetchComplianceRequests()),
  });
  const requests: AnyRequest[] = query.data?.requests ?? [];
  const refresh = () => void queryClient.invalidateQueries({ queryKey });

  const willPrefill = prefillId !== 'none';
  const target = willPrefill ? `${requestPath}?prefill=${prefillId}` : requestPath;

  return (
    <Flex direction="column" gap="3">
      {confirmDialog}
      <PageHeader title="Compliance" />

      {actionError && <ErrorAlert message={actionError} />}

      {!isAdminView && (
        <Flex>
          {requests.length === 0 
          ? <NewRequestButton requestPath={requestPath} />
          : <PrefillDialog prefillId={prefillId} setPrefillId={setPrefillId} requests={requests} target={target}/>
          }
        </Flex>
      )}

      {isAdminView && (
        <TextField.Root
          placeholder="Search by compliance request ID"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
      )}

      {query.isPending ? (
        <PageSpinner />
      ) : query.error ? (
        <ErrorAlert message="Failed to fetch compliance requests." />
      ) : (
        <ComplianceRequestTable isAdminView={isAdminView} requests={requests} filter={filter} refresh={refresh} setActionError={setActionError} requestPath={requestPath} confirm={confirm}/>
      )}
    </Flex>
  );
}

