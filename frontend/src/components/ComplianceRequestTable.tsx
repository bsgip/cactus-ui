import {
  Badge,
  Flex,
  Table,
  Text,
} from '@radix-ui/themes';
import {
  complianceArtifactUrl,
} from '../api/compliance';
import ActionButton from '../components/ActionButton';
import DateCell from '../components/DateCell';
import { actionsForStatus, statusLabel } from '../pages/Compliance/status';
import { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation } from '@tanstack/react-query';
import {
  adminUpdateComplianceRequest,
  deleteComplianceRequest,
} from '../api/compliance';

import { type ComplianceAction } from '../pages/Compliance/status';
import type { AdminComplianceRequestResponse, ComplianceRequestResponse } from '../api/types';
type AnyRequest = ComplianceRequestResponse | AdminComplianceRequestResponse;

function hasUser(r: AnyRequest): r is AdminComplianceRequestResponse {
  return 'created_by_user' in r;
}

interface ComplianceRequestTableProps {
	isAdminView: boolean;
	requests: AnyRequest[];
	filter: string;
  refresh: () => void;
  setActionError: React.Dispatch<React.SetStateAction<string|null>>;
  requestPath: string;
  confirm: any;
}

function ComplianceRequestTable({isAdminView, requests, filter, refresh, setActionError, requestPath, confirm} : ComplianceRequestTableProps) {
  const navigate = useNavigate();

  const filtered = useMemo(() => {
    const term = filter.trim();
    if (!term) return requests;
    return requests.filter((r) => String(r.compliance_request_id).includes(term));
  }, [requests, filter]);

  function handleAction(action: ComplianceAction, request: AnyRequest) {
    setActionError(null);
    const id = request.compliance_request_id;
    if (action === 'edit') {
      if (isAdminView) adminOpenMutation.mutate(id);
      else goToRequest(id, 'edit', request);
    } else if (action === 'view') {
      goToRequest(id, 'view', request);
    } else if (action === 'delete') {
      confirm({
        title: `Delete compliance request #${id}?`,
        body: 'This permanently deletes the compliance request and cannot be undone.',
        confirmLabel: 'Delete',
        confirmColor: 'red',
        onConfirm: () => deleteMutation.mutate(id),
      });
    }
    // 'download' is a plain link (rendered as an <a>), handled in the button below.
  }

  const deleteMutation = useMutation({
    mutationFn: (id: number) => deleteComplianceRequest(id, isAdminView),
    onSuccess: refresh,
    onError: (err: Error) => setActionError(err.message),
  });

  // Admin "edit" opens a submitted request for review: flip it to under_review, then navigate.
  const adminOpenMutation = useMutation({
    mutationFn: (id: number) => adminUpdateComplianceRequest(id, 'under_review'),
    onSuccess: (request) => {
      refresh();
      goToRequest(request.compliance_request_id, 'edit', request);
    },
    onError: (err: Error) => setActionError(err.message),
  });

  function goToRequest(id: number, action: 'edit' | 'view', request: AnyRequest) {
    navigate(
      `${requestPath}?prefill=${id}&prefill-classes=true&prefill-runs=true&action=${action}`,
      {
        state: { request },
      }
    );
  }

return (
        <Table.Root variant="surface">
          <Table.Header>
            <Table.Row>
              <Table.ColumnHeaderCell>#</Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell>Created</Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell>Witness Test</Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell>{isAdminView ? 'Client' : 'Classes'}</Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell>Status</Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell />
            </Table.Row>
          </Table.Header>
          <Table.Body>
            {filtered.length === 0 ? (
              <Table.Row>
                <Table.Cell colSpan={6} style={{ textAlign: 'center' }}>
                  No compliance requests found.
                </Table.Cell>
              </Table.Row>
            ) : (
              filtered.map((request) => (
                <Table.Row key={request.compliance_request_id}>
                  <Table.RowHeaderCell>{request.compliance_request_id}</Table.RowHeaderCell>
                  <Table.Cell>
                    <DateCell value={request.created_at} />
                  </Table.Cell>
                  <Table.Cell>
                    <DateCell value={request.witnessed_at} />
                  </Table.Cell>
                  <Table.Cell>
                    {isAdminView && hasUser(request) ? (
                      <>
                        {request.created_by_user.user_name ?? 'Unknown'}
                        <br />
                        <Text size="1" color="gray">
                          ID: {request.created_by_user.user_id}
                        </Text>
                      </>
                    ) : (
                      <Flex gap="1" wrap="wrap">
                        {request.classes.map((c) => (
                          <Badge key={c} color="gray">
                            {c}
                          </Badge>
                        ))}
                      </Flex>
                    )}
                  </Table.Cell>
                  <Table.Cell>{statusLabel(request.status, isAdminView)}</Table.Cell>
                  <Table.Cell>
                    <Flex gap="2" justify="end">
                      {actionsForStatus(request.status, isAdminView).map((action) => (
                        <ActionButton
                          key={action}
                          action={action}
                          downloadHref={complianceArtifactUrl(
                            request.compliance_request_id,
                            isAdminView
                          )}
                          onClick={() => handleAction(action, request)}
                        />
                      ))}
                    </Flex>
                  </Table.Cell>
                </Table.Row>
              ))
            )}
          </Table.Body>
        </Table.Root>
	)
}

export default ComplianceRequestTable;
