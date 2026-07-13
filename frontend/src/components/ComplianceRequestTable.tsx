import { Badge, Flex, Table } from '@radix-ui/themes';
import { useNavigate } from 'react-router-dom';
import { useMutation } from '@tanstack/react-query';

import { complianceArtifactUrl } from '../api/compliance';
import ActionButton from '../components/ActionButton';
import DateCell from '../components/DateCell';
import { deleteComplianceRequest } from '../api/compliance';
import { ComplianceStatus } from '../utils/complianceStatus';
import type { ComplianceAction } from '../pages/Compliance/status';
import type { ComplianceRequestResponse } from '../api/types';


interface ComplianceRequestTableProps {
	requests: ComplianceRequestResponse[];
  refresh: () => void;
  setActionError: React.Dispatch<React.SetStateAction<string|null>>;
  requestPath: string;
  confirm: any;
}

function ComplianceRequestTable({requests, refresh, setActionError, requestPath, confirm} : ComplianceRequestTableProps) {
  const navigate = useNavigate();

  function handleAction(action: ComplianceAction, request: ComplianceRequestResponse) {
    setActionError(null);
    const id = request.compliance_request_id;
    if (action === 'edit') {
      goToRequest(id, 'edit', request);
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
  }

  const deleteMutation = useMutation({
    mutationFn: (id: number) => deleteComplianceRequest(id),
    onSuccess: refresh,
    onError: (err: Error) => setActionError(err.message),
  });


  function goToRequest(id: number, action: 'edit' | 'view', request: ComplianceRequestResponse) {
    navigate(
      `${requestPath}?prefill=${id}&prefill-classes=true&prefill-runs=true&action=${action}`,
      {
        state: { request },
      }
    );
  }

  function statusLabel(status: number): string {
    switch (status) {
      case ComplianceStatus.SUBMITTED:
        return 'Submitted';
      case ComplianceStatus.UNDER_REVIEW:
        return 'Under Review';
      case ComplianceStatus.PUSHED_BACK:
        return 'Changes Requested';
      case ComplianceStatus.FINALISED:
        return 'Finalised';
      default:
        return `Unknown status: ${status}`;
    }
  };
    
  function actionsForStatus(status: number): ComplianceAction[] {
    switch (status) {
      case ComplianceStatus.SUBMITTED:
        return ['edit', 'delete'];
      case ComplianceStatus.UNDER_REVIEW:
        return ['view'];
      case ComplianceStatus.PUSHED_BACK:
        return ['edit', 'delete'];
      case ComplianceStatus.FINALISED:
        return ['view'];
      default:
        return [];
    }
  };

return (
        <Table.Root variant="surface">
          <Table.Header>
            <Table.Row>
              <Table.ColumnHeaderCell>#</Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell>Created</Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell>Witness Test</Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell>Classes</Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell>Status</Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell />
            </Table.Row>
          </Table.Header>
          <Table.Body>
            {requests.length === 0 ? (
              <Table.Row>
                <Table.Cell colSpan={6} style={{ textAlign: 'center' }}>
                  No compliance requests found.
                </Table.Cell>
              </Table.Row>
            ) : (
              requests.map((request) => (
                <Table.Row key={request.compliance_request_id}>
                  <Table.RowHeaderCell>{request.compliance_request_id}</Table.RowHeaderCell>
                  <Table.Cell>
                    <DateCell value={request.created_at} />
                  </Table.Cell>
                  <Table.Cell>
                    <DateCell value={request.witnessed_at} />
                  </Table.Cell>
                  <Table.Cell>
                    <Flex gap="1" wrap="wrap">
                      {request.classes.map((c) => (
                        <Badge key={c} color="gray">
                          {c}
                        </Badge>
                      ))}
                    </Flex>
                  </Table.Cell>
                  <Table.Cell>{statusLabel(request.status)}</Table.Cell>
                  <Table.Cell>
                    <Flex gap="2" justify="end">
                      {actionsForStatus(request.status).map((action) => (
                        <ActionButton
                          key={action}
                          action={action}
                          downloadHref={complianceArtifactUrl(
                            request.compliance_request_id,
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
