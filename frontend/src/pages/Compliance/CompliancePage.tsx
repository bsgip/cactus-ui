import {
  Badge,
  Button,
  Dialog,
  Flex,
  IconButton,
  Select,
  Table,
  Text,
  TextField,
} from '@radix-ui/themes';
import { IconDownload, IconEye, IconPencil, IconPlus, IconTrash } from '@tabler/icons-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useMemo, useState } from 'react';
import { Link as RouterLink, useNavigate } from 'react-router-dom';
import {
  adminUpdateComplianceRequest,
  complianceArtifactUrl,
  deleteComplianceRequest,
  fetchAdminComplianceRequests,
  fetchComplianceRequests,
} from '../../api/compliance';
import type { AdminComplianceRequestResponse, ComplianceRequestResponse } from '../../api/types';
import { ErrorAlert } from '../../components/ErrorAlert';
import { PageHeader } from '../../components/PageHeader';
import { PageSpinner } from '../../components/PageSpinner';
import DateCell from '../../components/DateCell';
import { useConfirm } from '../../components/useConfirm';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import { actionsForStatus, statusLabel, type ComplianceAction } from './status';

type AnyRequest = ComplianceRequestResponse | AdminComplianceRequestResponse;

function hasUser(r: AnyRequest): r is AdminComplianceRequestResponse {
  return 'created_by_user' in r;
}


// One component for both views: isAdminView selects the admin endpoints, columns, status
// wording, and the per-status action set.
export function CompliancePage({ isAdminView }: { isAdminView: boolean }) {
  useDocumentTitle('Compliance - CACTUS');
  const navigate = useNavigate();
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

  const filtered = useMemo(() => {
    const term = filter.trim();
    if (!term) return requests;
    return requests.filter((r) => String(r.compliance_request_id).includes(term));
  }, [requests, filter]);

  return (
    <Flex direction="column" gap="3">
      {confirmDialog}
      <PageHeader title="Compliance" />

      {actionError && <ErrorAlert message={actionError} />}

      {!isAdminView && (
        <Flex>
          <NewRequestButton
            requestPath={requestPath}
            requests={requests as ComplianceRequestResponse[]}
            prefillId={prefillId}
            setPrefillId={setPrefillId}
          />
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
      )}
    </Flex>
  );
}

const ACTION_META: Record<
  ComplianceAction,
  {
    icon: typeof IconPencil;
    color: React.ComponentProps<typeof IconButton>['color'];
    tooltip: string;
  }
> = {
  edit: { icon: IconPencil, color: 'blue', tooltip: 'Review / edit compliance request' },
  view: { icon: IconEye, color: 'gray', tooltip: 'View compliance request' },
  download: { icon: IconDownload, color: 'gray', tooltip: 'Download compliance report' },
  delete: { icon: IconTrash, color: 'red', tooltip: 'Delete compliance request (permanent)' },
};

function ActionButton({
  action,
  downloadHref,
  onClick,
}: {
  action: ComplianceAction;
  downloadHref: string;
  onClick: () => void;
}) {
  const { icon: Icon, color, tooltip } = ACTION_META[action];
  if (action === 'download') {
    return (
      <IconButton asChild variant="outline" color={color} title={tooltip}>
        <a href={downloadHref}>
          <Icon size={16} />
        </a>
      </IconButton>
    );
  }
  return (
    <IconButton variant="outline" color={color} title={tooltip} onClick={onClick}>
      <Icon size={16} />
    </IconButton>
  );
}

// "New Request": navigates straight to a blank wizard, or — when the user has prior requests —
// offers to prefill the new request's details from an existing one (without copying classes/runs).
function NewRequestButton({
  requestPath,
  requests,
  prefillId,
  setPrefillId,
}: {
  requestPath: string;
  requests: ComplianceRequestResponse[];
  prefillId: string;
  setPrefillId: (id: string) => void;
}) {
  if (requests.length === 0) {
    return (
      <Button asChild size="3">
        <RouterLink to={requestPath}>
          <IconPlus size={16} /> New Request
        </RouterLink>
      </Button>
    );
  }

  const willPrefill = prefillId !== 'none';
  const target = willPrefill ? `${requestPath}?prefill=${prefillId}` : requestPath;

  return (
    <Dialog.Root>
      <Dialog.Trigger>
        <Button size="3">
          <IconPlus size={16} /> New Request
        </Button>
      </Dialog.Trigger>
      <Dialog.Content maxWidth="500px">
        <Dialog.Title>New request for compliance</Dialog.Title>
        <Dialog.Description size="2" mb="3">
          To save time, a new compliance request can be pre-filled with the details (DER, software
          client) of an existing request. Classes and runs are not copied.
        </Dialog.Description>
        <Text as="label" size="2" weight="bold">
          Pre-fill from
        </Text>
        <Select.Root value={prefillId} onValueChange={setPrefillId}>
          <Select.Trigger placeholder="No pre-fill" mt="1" />
          <Select.Content>
            <Select.Item value="none">No pre-fill</Select.Item>
            {requests.map((r) => (
              <Select.Item key={r.compliance_request_id} value={String(r.compliance_request_id)}>
                Compliance Request #{r.compliance_request_id}
              </Select.Item>
            ))}
          </Select.Content>
        </Select.Root>
        <Flex gap="3" mt="4" justify="end">
          <Dialog.Close>
            <Button variant="soft" color="gray">
              Cancel
            </Button>
          </Dialog.Close>
          <Button asChild>
            <RouterLink to={target}>{prefillId ? 'Pre-fill request' : 'Continue'}</RouterLink>
          </Button>
        </Flex>
      </Dialog.Content>
    </Dialog.Root>
  );
}
