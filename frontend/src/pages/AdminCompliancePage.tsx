import { Flex, TextField } from '@radix-ui/themes';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';

import { fetchAdminComplianceRequests } from '../api/compliance';
import { ErrorAlert } from '../components/ErrorAlert';
import { PageHeader } from '../components/PageHeader';
import { PageSpinner } from '../components/PageSpinner';
import { useConfirm } from '../components/useConfirm';
import { useDocumentTitle } from '../hooks/useDocumentTitle';
import AdminComplianceRequestTable from '../components/AdminComplianceRequestTable';
import type { AdminComplianceRequestResponse} from '../api/types';


export function AdminCompliancePage() {
  useDocumentTitle('Compliance - CACTUS');
  const queryClient = useQueryClient();
  const { confirm, confirmDialog } = useConfirm();
  const [filter, setFilter] = useState('');
  const [actionError, setActionError] = useState<string | null>(null);

  const requestPath = '/admin/compliance-request';
  const queryKey = ['compliance', 'requests'];
  const query = useQuery({
    queryKey,
    queryFn: () => fetchAdminComplianceRequests(),
  });
  const requests: AdminComplianceRequestResponse[] = query.data?.requests ?? [];
  const refresh = () => void queryClient.invalidateQueries({ queryKey });


  return (
    <Flex direction="column" gap="3">
      {confirmDialog}
      <PageHeader title="Compliance" />

      {actionError && <ErrorAlert message={actionError} />}

      <TextField.Root
        placeholder="Search by compliance request ID"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
      />

      {query.isPending ? (
        <PageSpinner />
      ) : query.error ? (
        <ErrorAlert message="Failed to fetch compliance requests." />
      ) : (
        <AdminComplianceRequestTable requests={requests} filter={filter} refresh={refresh} setActionError={setActionError} requestPath={requestPath} confirm={confirm}/>
      )}
    </Flex>
  );
}

