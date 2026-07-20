import {
  Button,
  Flex,
  Heading,
} from '@radix-ui/themes';
import { useQuery } from '@tanstack/react-query';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { useState } from 'react';

import {
  fetchComplianceFormData,
  fetchComplianceRequest,
} from '../api/compliance';
import type {
  ComplianceRequestResponse,
} from '../api/types';
import { ErrorAlert } from '../components/ErrorAlert';
import { PageSpinner } from '../components/PageSpinner';
import { useConfirm } from '../components/useConfirm';
import { useDocumentTitle } from '../hooks/useDocumentTitle';
import { Mode } from '../utils/complianceRequestForm';
import ComplianceRequestWizard from '../components/ComplianceRequestWizard';


export function ComplianceRequestPage({ isAdminView }: { isAdminView: boolean }) {
  useDocumentTitle('Compliance Request - CACTUS');

  const navigate = useNavigate();
  const gotoComplianceList = () => navigate(isAdminView ? '/admin/compliance' : '/compliance');

  const [actionError, setActionError] = useState<string | null>(null);

  const { confirm, confirmDialog } = useConfirm();

  const [searchParams] = useSearchParams();
  const prefillId = searchParams.get('prefill');
  const requestId = prefillId ? Number(prefillId) : null;

  const action = searchParams.get('action');
  const mode: Mode = action === 'edit' ? 'edit' : action === 'view' ? 'view' : 'new';
  const readOnly = mode === 'view';

  // The request to prefill from: passed via navigation state from the list, else fetched.
  const location = useLocation();
  const stateRequest = (location.state as { request?: ComplianceRequestResponse } | null)?.request;
  const formDataQuery = useQuery({
    queryKey: ['compliance', 'form-data'],
    queryFn: fetchComplianceFormData,
  });
  const prefillQuery = useQuery({
    queryKey: ['compliance', 'request', requestId],
    queryFn: () => fetchComplianceRequest(requestId as number),
    enabled: requestId !== null && !stateRequest,
  });
  const prefillRequest = stateRequest ?? prefillQuery.data;

  const formData = formDataQuery.data;


  const handleClose = () => {
    if (readOnly) {
      gotoComplianceList();
      return;
    }
    confirm({
      title: 'Are you sure you want to leave?',
      body: 'You will lose all information entered.',
      confirmLabel: 'Leave',
      cancelLabel: 'Continue with compliance request',
      confirmColor: 'red',
      onConfirm: gotoComplianceList,
    });
  };

  if (formDataQuery.isPending || (requestId !== null && !stateRequest && prefillQuery.isPending)) {
    return <PageSpinner />;
  }
  if (formDataQuery.error || !formData) {
    return (
      <ErrorAlert message="Failed to fetch test procedures. Unable to continue with the compliance request." />
    );
  }


  return (
    <Flex direction="column" gap="4">
      {confirmDialog}
      <Flex justify="between" align="center">
        <Heading as="h2" size="6">
          Compliance Request
        </Heading>
        <Button variant="ghost" color="gray" onClick={handleClose}>
          Close
        </Button>
      </Flex>

      {actionError && <ErrorAlert message={actionError} />}

      <ComplianceRequestWizard
        isAdminView={isAdminView}
        setActionError={setActionError}
        formData={formData}
        prefillRequest={prefillRequest}
      />

      <iframe name="complianceFinaliseFrame" title="finalise" style={{ display: 'none' }} />
    </Flex>
  );
}


