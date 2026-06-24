import { ActionIcon, Anchor, Button, Center, Loader, Table, Text } from '@mantine/core';
import { IconCheck, IconQuestionMark, IconTrash, IconX } from '@tabler/icons-react';
import { Link } from 'react-router-dom';
import type { RunResponse } from '../../api/types';
import { formatDate, formatRelativeDate } from '../../utils/dates';

export interface PendingRunAction {
  kind: 'start' | 'finalise' | 'delete';
  runId: number;
}

interface RunsTableProps {
  runs: RunResponse[] | undefined;
  isPending: boolean;
  error: Error | null;
  isAdminView: boolean;
  pendingAction: PendingRunAction | null;
  onStart: (runId: number) => void;
  onFinalise: (runId: number) => void;
  onDelete: (runId: number) => void;
}

function isLiveStatus(run: RunResponse): boolean {
  return run.status === 'initialised' || run.status === 'started';
}

function rowBackground(run: RunResponse): string | undefined {
  if (run.all_criteria_met === true) {
    return 'var(--mantine-color-green-0)';
  }
  if (run.all_criteria_met === false) {
    return 'var(--mantine-color-red-0)';
  }
  return isLiveStatus(run) ? 'var(--mantine-color-blue-0)' : undefined;
}

function ResultIcon({ run }: { run: RunResponse }) {
  if (run.all_criteria_met === true) {
    return <IconCheck size={16} color="var(--mantine-color-green-7)" aria-label="criteria met" />;
  }
  if (run.all_criteria_met === false) {
    return <IconX size={16} color="var(--mantine-color-red-7)" aria-label="criteria not met" />;
  }
  if (!isLiveStatus(run)) {
    return (
      <IconQuestionMark size={16} color="var(--mantine-color-gray-6)" aria-label="result unknown" />
    );
  }
  return null;
}

function ActionButton({
  run,
  isAdminView,
  pendingAction,
  onStart,
  onFinalise,
}: Pick<RunsTableProps, 'isAdminView' | 'pendingAction' | 'onStart' | 'onFinalise'> & {
  run: RunResponse;
}) {
  if (isAdminView) {
    // Admins shouldn't be starting or finalising tests for other users.
    if (isLiveStatus(run)) {
      return (
        <Button disabled color="gray">
          Running...
        </Button>
      );
    }
    if (run.has_artifacts) {
      return (
        <Button component="a" href={`/admin/run/${run.run_id}/artifact`} color="gray">
          Download
        </Button>
      );
    }
    return null;
  }

  if (run.status === 'initialised') {
    return (
      <Button
        onClick={() => onStart(run.run_id)}
        loading={pendingAction?.kind === 'start' && pendingAction.runId === run.run_id}
      >
        Start
      </Button>
    );
  }
  if (run.status === 'started') {
    return (
      <Button
        color="yellow"
        onClick={() => onFinalise(run.run_id)}
        loading={pendingAction?.kind === 'finalise' && pendingAction.runId === run.run_id}
      >
        Finalise
      </Button>
    );
  }
  if (run.has_artifacts) {
    return (
      <Button component="a" href={`/run/${run.run_id}/artifact`} color="gray">
        Download
      </Button>
    );
  }
  return null;
}

export function RunsTable({
  runs,
  isPending,
  error,
  isAdminView,
  pendingAction,
  onStart,
  onFinalise,
  onDelete,
}: RunsTableProps) {
  let body;
  if (isPending) {
    body = (
      <Table.Tr>
        <Table.Td colSpan={6}>
          <Center py="md">
            <Loader color="green" />
          </Center>
        </Table.Td>
      </Table.Tr>
    );
  } else if (error) {
    body = (
      <Table.Tr bg="var(--mantine-color-red-0)">
        <Table.Td colSpan={6}>{error.message}</Table.Td>
      </Table.Tr>
    );
  } else if (!runs || runs.length === 0) {
    body = (
      <Table.Tr>
        <Table.Td colSpan={6}>No runs were returned.</Table.Td>
      </Table.Tr>
    );
  } else {
    body = runs.map((run) => {
      const created = new Date(run.created_at);
      return (
        <Table.Tr key={run.run_id} bg={rowBackground(run)}>
          <Table.Td>
            <Anchor component={Link} to={`${isAdminView ? '/admin' : ''}/run/${run.run_id}`}>
              {run.run_id}
            </Anchor>
          </Table.Td>
          <Table.Td>
            {formatDate(created)}
            <br />
            <Text component="small" size="xs" c="dimmed">
              ({formatRelativeDate(created)})
            </Text>
          </Table.Td>
          <Table.Td>{run.status}</Table.Td>
          <Table.Td>
            <ResultIcon run={run} />
          </Table.Td>
          <Table.Td>
            <ActionButton
              run={run}
              isAdminView={isAdminView}
              pendingAction={pendingAction}
              onStart={onStart}
              onFinalise={onFinalise}
            />
          </Table.Td>
          <Table.Td>
            {!isAdminView && (
              <ActionIcon
                variant="outline"
                color="red"
                size="lg"
                aria-label={`Delete run ${run.run_id}`}
                loading={pendingAction?.kind === 'delete' && pendingAction.runId === run.run_id}
                onClick={() => onDelete(run.run_id)}
              >
                <IconTrash size={16} />
              </ActionIcon>
            )}
          </Table.Td>
        </Table.Tr>
      );
    });
  }

  return (
    <Table>
      <Table.Tbody>{body}</Table.Tbody>
    </Table>
  );
}
