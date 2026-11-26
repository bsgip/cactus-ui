import {
  Badge,
  Button,
  Flex,
  IconButton,
  Link,
  Table,
  Text,
  TextField,
  Tooltip,
} from '@radix-ui/themes';
import { IconPencil, IconPlus, IconX } from '@tabler/icons-react';
import { useMutation, useQueryClient, UseMutationResult } from '@tanstack/react-query';
import { Dispatch, SetStateAction, useRef, useState, RefObject } from 'react';
import { Link as RouterLink } from 'react-router-dom';

import { deleteRunGroup, updateRunGroupName } from '../api/config';
import { CopyButton } from './CopyButton';
import { InfoPopover } from './InfoPopover';
import { AssignCertificateModal } from './AssignCertificateModal';
import { DeleteModal } from './DeleteModal';
import { NewCertificateModal } from './NewCertificateModal';
import { certExpiryStatus, certTypeLabel, formatCertDate } from '../utils/certificates';
import type { CertificateResponse, RunGroupResponse } from '../api/types';

function CertStatusBadge({
  runGroup,
  certificate,
}: {
  runGroup: RunGroupResponse;
  certificate: CertificateResponse | undefined;
}) {
  if (runGroup.assigned_certificate_id == null) {
    return (
      <Flex direction="column" gap="1">
        <Badge color="amber">No certificate</Badge>
        <Text size="1" color="gray">
          required before running tests
        </Text>
      </Flex>
    );
  }

  const certType = certTypeLabel(!!runGroup.is_device_cert);
  const expiry = certificate ? certExpiryStatus(certificate.expires_at) : 'valid';
  const sharedWith = certificate ? certificate.run_group_ids.length - 1 : 0;

  return (
    <Flex direction="column" gap="1">
      <Tooltip
        content={
          certificate
            ? `Issued ${formatCertDate(certificate.generated_at)}, expires ${formatCertDate(certificate.expires_at)}`
            : runGroup.certificate_name
        }
      >
        <Badge color={expiry === 'expired' ? 'red' : expiry === 'expiring' ? 'amber' : 'green'}>
          {certType} cert · {runGroup.certificate_name}
          {expiry === 'expired' && ' · expired'}
        </Badge>
      </Tooltip>
      {sharedWith > 0 && (
        <Text size="1" color="gray">
          shared with {sharedWith} other {sharedWith === 1 ? 'group' : 'groups'}
        </Text>
      )}
    </Flex>
  );
}

function RunGroupConfigTableHeader() {
  return (
    <Table.Header>
      <Table.Row>
        <Table.ColumnHeaderCell>Certificate</Table.ColumnHeaderCell>
        <Table.ColumnHeaderCell>Name</Table.ColumnHeaderCell>
        <Table.ColumnHeaderCell>Version</Table.ColumnHeaderCell>
        <Table.ColumnHeaderCell>
          <Flex align="center" gap="1">
            DeviceCapability URI
            <InfoPopover title="DeviceCapability URI">
              Each run group has a single, fixed DeviceCapability URI shared across all of its
              test runs. Because the URI is fixed per group, only one test run can be active
              in a group at a time, and the URI only responds once a run has been started from
              the Runs page.
            </InfoPopover>
          </Flex>
        </Table.ColumnHeaderCell>
        <Table.ColumnHeaderCell>Runs</Table.ColumnHeaderCell>
        <Table.ColumnHeaderCell />
      </Table.Row>
    </Table.Header>
  );
}


function CertificateCell({
  rg,
  runGroups,
  certificates,
  hasDomain,
  onCertAction,
  setError,
}: {
  rg: RunGroupResponse;
  runGroups: RunGroupResponse[];
  certificates: CertificateResponse[];
  hasDomain: boolean;
  onCertAction: (message: string) => void;
  setError: (msg: string | null) => void;
}) {
  const certificate = certificates.find((c) => c.certificate_id === rg.assigned_certificate_id);
  return (
    <Table.Cell>
      <Flex direction="column" gap="2" align="start">
        <CertStatusBadge runGroup={rg} certificate={certificate} />
        <Flex gap="2">
          {certificates.length > 0 && (
            <AssignCertificateModal
              runGroup={rg}
              runGroups={runGroups}
              certificates={certificates}
              onCertAction={onCertAction}
              onCertError={setError}
            />
          )}
          <NewCertificateModal
            runGroups={runGroups}
            hasDomain={hasDomain}
            defaultRunGroupIds={[rg.run_group_id]}
            onCreated={onCertAction}
            onError={setError}
            trigger={(open) =>
              certificates.length === 0 ? (
                <Button size="1" onClick={open}>
                  <IconPlus size={14} />
                  Generate Certificate
                </Button>
              ) : (
                <Button size="1" variant="outline" onClick={open}>
                  <IconPlus size={14} />
                  New
                </Button>
              )
            }
          />
        </Flex>
      </Flex>
    </Table.Cell>
  );
}

function RunGroupNameCell({ rg, updateNameMutation, editing, setEditing }: { rg: RunGroupResponse, updateNameMutation: UseMutationResult<RunGroupResponse, Error, { id: number; name: string; }, unknown>, editing: { id: number; draft: string; } | null, setEditing: Dispatch<SetStateAction<{ id: number; draft: string; } | null>> }) {
  return (
    <Table.Cell>
      {editing?.id === rg.run_group_id ? (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const name = editing.draft.trim();
            if (name && name !== rg.name) {
              updateNameMutation.mutate(
                { id: rg.run_group_id, name },
                { onSuccess: () => setEditing(null) }
              );
            }
          }}
        >
          <Flex gap="2" align="center">
            <TextField.Root
              autoFocus
              value={editing.draft}
              onChange={(e) =>
                setEditing({ id: rg.run_group_id, draft: e.target.value })
              }
              onKeyDown={(e) => {
                if (e.key === 'Escape') setEditing(null);
              }}
              style={{ flex: 1 }}
            />
            <Button
              type="submit"
              variant="outline"
              disabled={editing.draft.trim() === '' || editing.draft.trim() === rg.name}
              loading={
                updateNameMutation.isPending &&
                updateNameMutation.variables?.id === rg.run_group_id
              }
            >
              Save
            </Button>
            <IconButton
              type="button"
              variant="ghost"
              color="gray"
              onClick={() => setEditing(null)}
              aria-label="Cancel"
            >
              <IconX size={14} />
            </IconButton>
          </Flex>
        </form>
      ) : (
        <Flex gap="2" align="center">
          <Text>{rg.name}</Text>
          <IconButton
            type="button"
            variant="ghost"
            color="gray"
            onClick={() => setEditing({ id: rg.run_group_id, draft: rg.name })}
            aria-label="Rename"
          >
            <IconPencil size={14} />
          </IconButton>
        </Flex>
      )}
    </Table.Cell>
  );
};

function CsipAusVersionCell({ rg }: { rg: RunGroupResponse }) {
  return (
    <Table.Cell>
      <Text>{rg.csip_aus_version}</Text>
    </Table.Cell>
  );
};

function DeviceCapabilityUriCell({ rg }: { rg: RunGroupResponse }) {
  return (
    <Table.Cell>
      {rg.static_uri ? (
        <Flex align="center" gap="1">
          <Text
            style={{ whiteSpace: 'nowrap', overflowX: 'auto', maxWidth: 220, scrollbarWidth: "thin" }}
          >
            {rg.static_uri}
          </Text>
          <CopyButton value={rg.static_uri} />
        </Flex>
      ) : (
        <Text size="1" color="gray">
          —
        </Text>
      )}
    </Table.Cell>

  );
};

function RunsCell({ rg }: { rg: RunGroupResponse }) {
  return (
    <Table.Cell>
      <Link asChild>
        <RouterLink to={`/group/${rg.run_group_id}/runs`}>
          {rg.total_runs} {rg.total_runs === 1 ? 'run' : 'runs'}
        </RouterLink>
      </Link>
    </Table.Cell>

  );
};

function DeleteRunGroupCell({ rg, deleteMutation, pendingDeleteRef }: { rg: RunGroupResponse, deleteMutation: UseMutationResult<Record<string, never>, Error, number, unknown>, pendingDeleteRef: RefObject<number | null> }) {
  return (
    <Table.Cell>
      <DeleteModal
        runGroup={rg}
        isDeleting={
          deleteMutation.isPending && pendingDeleteRef.current === rg.run_group_id
        }
        onDelete={() => {
          pendingDeleteRef.current = rg.run_group_id;
          deleteMutation.mutate(rg.run_group_id);
        }}
      />
    </Table.Cell>

  );
};

interface RunGroupConfigTableRowProps {
  rg: RunGroupResponse;
  runGroups: RunGroupResponse[];
  certificates: CertificateResponse[];
  hasDomain: boolean;
  onCertAction: (message: string) => void;
  setError: (msg: string | null) => void;
  deleteMutation: UseMutationResult<Record<string, never>, Error, number, unknown>;
  editing: { id: number; draft: string; } | null;
  setEditing: Dispatch<SetStateAction<{ id: number; draft: string; } | null>>;
  pendingDeleteRef: RefObject<number | null>;
  updateNameMutation: UseMutationResult<RunGroupResponse, Error, { id: number; name: string; }, unknown>
};

function RunGroupConfigTableRow({ rg, runGroups, certificates, hasDomain, onCertAction, deleteMutation, editing, setEditing, pendingDeleteRef, updateNameMutation, setError }: RunGroupConfigTableRowProps) {
  return (
    <Table.Row>
      <CertificateCell
        rg={rg}
        runGroups={runGroups}
        certificates={certificates}
        hasDomain={hasDomain}
        onCertAction={onCertAction}
        setError={setError}
      />
      <RunGroupNameCell rg={rg} updateNameMutation={updateNameMutation} editing={editing} setEditing={setEditing} />
      <CsipAusVersionCell rg={rg} />
      <DeviceCapabilityUriCell rg={rg} />
      <RunsCell rg={rg} />
      <DeleteRunGroupCell rg={rg} deleteMutation={deleteMutation} pendingDeleteRef={pendingDeleteRef} />
    </Table.Row>
  );
}


interface RunGroupConfigTableProps {
  runGroups: RunGroupResponse[];
  certificates: CertificateResponse[];
  hasDomain: boolean;
  onCertAction: (message: string) => void;
  setError: (msg: string | null) => void;
}

function RunGroupConfigTable({ runGroups, certificates, hasDomain, onCertAction, setError }: RunGroupConfigTableProps) {
  const queryClient = useQueryClient();

  // Returning the invalidation promise keeps each mutation pending (spinners showing) until the
  // refetched config lands, so the UI never flashes stale data between save and refetch.
  const onSuccess = () => {
    setError(null);
    return queryClient.invalidateQueries({ queryKey: ['config'] });
  };
  const onError = (err: Error) => setError(err.message);

  const [editing, setEditing] = useState<{ id: number; draft: string } | null>(null);

  const pendingDeleteRef = useRef<number | null>(null);

  const updateNameMutation = useMutation({
    mutationFn: ({ id, name }: { id: number; name: string }) => updateRunGroupName(id, name),
    onSuccess,
    onError,
  });
  const deleteMutation = useMutation({
    mutationFn: (id: number) => deleteRunGroup(id),
    onSuccess,
    onError,
  });

  return (
    <Table.Root variant="surface">
      <RunGroupConfigTableHeader />
      <Table.Body>
        {runGroups.map((rg) => (
          <RunGroupConfigTableRow key={rg.run_group_id} rg={rg} runGroups={runGroups} certificates={certificates} hasDomain={hasDomain} onCertAction={onCertAction} deleteMutation={deleteMutation} editing={editing} setEditing={setEditing} pendingDeleteRef={pendingDeleteRef} updateNameMutation={updateNameMutation} setError={setError} />
        ))}
      </Table.Body>
    </Table.Root>
  );
}

export default RunGroupConfigTable
