import { Button, Flex, IconButton, Link, Spinner, Table, Text } from '@radix-ui/themes';
import { IconCheck, IconQuestionMark, IconTrash, IconX } from '@tabler/icons-react';
import { Link as RouterLink } from 'react-router-dom';
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
    return 'var(--green-2)';
  }
  if (run.all_criteria_met === false) {
    return 'var(--red-2)';
  }
  return isLiveStatus(run) ? 'var(--blue-2)' : undefined;
}

function ResultIcon({ run }: { run: RunResponse }) {
  if (run.all_criteria_met === true) {
    return <IconCheck size={16} color="var(--green-9)" aria-label="criteria met" />;
  }
  if (run.all_criteria_met === false) {
    return <IconX size={16} color="var(--red-9)" aria-label="criteria not met" />;
  }
  if (!isLiveStatus(run)) {
    return <IconQuestionMark size={16} color="var(--gray-9)" aria-label="result unknown" />;
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
        <Button asChild color="gray">
          <a href={`/admin/run/${run.run_id}/artifact`}>Download</a>
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
      <Button asChild color="gray">
        <a href={`/run/${run.run_id}/artifact`}>Download</a>
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
      <Table.Row>
        <Table.Cell colSpan={6}>
          <Flex justify="center" py="3">
            <Spinner />
          </Flex>
        </Table.Cell>
      </Table.Row>
    );
  } else if (error) {
    body = (
      <Table.Row style={{ backgroundColor: 'var(--red-2)' }}>
        <Table.Cell colSpan={6}>{error.message}</Table.Cell>
      </Table.Row>
    );
  } else if (!runs || runs.length === 0) {
    body = (
      <Table.Row>
        <Table.Cell colSpan={6}>No runs were returned.</Table.Cell>
      </Table.Row>
    );
  } else {
    body = runs.map((run) => {
      const created = new Date(run.created_at);
      return (
        <Table.Row key={run.run_id} style={{ backgroundColor: rowBackground(run) }}>
          <Table.Cell>
            <Link asChild>
              <RouterLink to={`${isAdminView ? '/admin' : ''}/run/${run.run_id}`}>
                {run.run_id}
              </RouterLink>
            </Link>
          </Table.Cell>
          <Table.Cell>
            {formatDate(created)}
            <br />
            <Text size="1" color="gray">
              ({formatRelativeDate(created)})
            </Text>
          </Table.Cell>
          <Table.Cell>{run.status}</Table.Cell>
          <Table.Cell>
            <ResultIcon run={run} />
          </Table.Cell>
          <Table.Cell>
            <ActionButton
              run={run}
              isAdminView={isAdminView}
              pendingAction={pendingAction}
              onStart={onStart}
              onFinalise={onFinalise}
            />
          </Table.Cell>
          <Table.Cell>
            {!isAdminView && (
              <IconButton
                variant="outline"
                color="red"
                size="2"
                aria-label={`Delete run ${run.run_id}`}
                loading={pendingAction?.kind === 'delete' && pendingAction.runId === run.run_id}
                onClick={() => onDelete(run.run_id)}
              >
                <IconTrash size={16} />
              </IconButton>
            )}
          </Table.Cell>
        </Table.Row>
      );
    });
  }

  return (
    <Table.Root variant="surface">
      <Table.Body>{body}</Table.Body>
    </Table.Root>
  );
}
