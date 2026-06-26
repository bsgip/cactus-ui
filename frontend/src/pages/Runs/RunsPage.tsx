import { Box, Button, DropdownMenu, Flex, Heading, Link, Separator, Text } from '@radix-ui/themes';
import { IconChevronDown } from '@tabler/icons-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { Link as RouterLink, useNavigate, useParams } from 'react-router-dom';
import {
  deleteRun,
  fetchActiveRuns,
  fetchProcedureRuns,
  fetchProcedureSummaries,
  fetchRunGroups,
  finaliseRun,
  initRun,
  startRun,
} from '../../api/runs';
import { Banner } from '../../components/Banner';
import { ErrorAlert } from '../../components/ErrorAlert';
import { PageSpinner } from '../../components/PageSpinner';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import { useSession } from '../../hooks/useSession';
import { ProcedureList } from './ProcedureList';
import { RunsTable, type PendingRunAction } from './RunsTable';

export type RunsSelection =
  | { kind: 'active' }
  | { kind: 'procedure'; id: string; description: string };

const POLL_INTERVAL_MS = 10_000;
const LIVE_STATUSES = new Set(['initialised', 'started', 'provisioning']);

// One component for both the user and admin views: isAdminView selects /api vs /api/admin
// paths and gates the run lifecycle controls.
export function RunsPage({ isAdminView }: { isAdminView: boolean }) {
  useDocumentTitle('Runs - CACTUS');
  const { runGroupId: runGroupIdParam } = useParams();
  const runGroupId = Number(runGroupIdParam);
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { data: session } = useSession();

  const [selection, setSelection] = useState<RunsSelection>({ kind: 'active' });
  const [actionError, setActionError] = useState<string | null>(null);

  useEffect(() => {
    setSelection({ kind: 'active' });
    setActionError(null);
  }, [runGroupId, isAdminView]);

  const groupsQuery = useQuery({
    queryKey: ['run_groups', isAdminView ? runGroupId : 'mine'],
    queryFn: () => fetchRunGroups(isAdminView, runGroupId),
  });

  const summariesQuery = useQuery({
    queryKey: ['procedure_summaries', runGroupId, isAdminView],
    queryFn: () => fetchProcedureSummaries(runGroupId, isAdminView),
  });

  const runsQuery = useQuery({
    queryKey: [
      'runs',
      runGroupId,
      selection.kind === 'active' ? 'active' : selection.id,
      isAdminView,
    ],
    queryFn: () =>
      selection.kind === 'active'
        ? fetchActiveRuns(runGroupId, isAdminView)
        : fetchProcedureRuns(runGroupId, selection.id, isAdminView),
    // Poll while something can still change: always on the Active Runs view, otherwise
    // only while the listed runs contain a live one.
    refetchInterval: (query) => {
      if (selection.kind === 'active') {
        return POLL_INTERVAL_MS;
      }
      const items = query.state.data?.items;
      return items?.some((r) => LIVE_STATUSES.has(r.status)) ? POLL_INTERVAL_MS : false;
    },
  });

  const invalidateRunData = () => {
    void queryClient.invalidateQueries({ queryKey: ['runs', runGroupId] });
    void queryClient.invalidateQueries({ queryKey: ['procedure_summaries', runGroupId] });
  };

  const onActionError = (error: Error) => setActionError(error.message);

  // Initialise and start both hand over to the run status page for the new run.
  const initMutation = useMutation({
    mutationFn: (testProcedureId: string) => initRun(runGroupId, testProcedureId),
    onSuccess: ({ run_id }) => void navigate(`/run/${run_id}`),
    onError: onActionError,
  });
  const startMutation = useMutation({
    mutationFn: startRun,
    onSuccess: ({ run_id }) => void navigate(`/run/${run_id}`),
    onError: onActionError,
  });
  const finaliseMutation = useMutation({
    mutationFn: finaliseRun,
    onSuccess: invalidateRunData,
    onError: onActionError,
  });
  const deleteMutation = useMutation({
    mutationFn: deleteRun,
    onSuccess: invalidateRunData,
    onError: onActionError,
  });

  let pendingAction: PendingRunAction | null = null;
  if (startMutation.isPending) {
    pendingAction = { kind: 'start', runId: startMutation.variables };
  } else if (finaliseMutation.isPending) {
    pendingAction = { kind: 'finalise', runId: finaliseMutation.variables };
  } else if (deleteMutation.isPending) {
    pendingAction = { kind: 'delete', runId: deleteMutation.variables };
  }

  const runGroups = groupsQuery.data?.items ?? [];
  const activeRunGroup = runGroups.find((rg) => rg.run_group_id === runGroupId);
  const groupRunsPath = (id: number) => `${isAdminView ? '/admin' : ''}/group/${id}/runs`;

  return (
    <>
      <Banner message={session?.banner_message} />
      {groupsQuery.error && <ErrorAlert message="Unable to fetch run groups." />}
      {actionError && <ErrorAlert message={actionError} />}

      <Flex justify="between" align="center" mb="1">
        <Flex gap="2" align="center">
          <Heading as="h2" size="6">
            Runs for
          </Heading>
          {runGroups.length < 2 ? (
            activeRunGroup && (
              <Heading as="h2" size="6">
                {activeRunGroup.name}
              </Heading>
            )
          ) : (
            <DropdownMenu.Root>
              <DropdownMenu.Trigger>
                <Button color="blue">
                  {activeRunGroup?.name}
                  <IconChevronDown size={16} />
                </Button>
              </DropdownMenu.Trigger>
              <DropdownMenu.Content>
                {runGroups
                  .filter((rg) => rg.run_group_id !== runGroupId)
                  .map((rg) => (
                    <DropdownMenu.Item
                      key={rg.run_group_id}
                      onSelect={() => navigate(groupRunsPath(rg.run_group_id))}
                    >
                      {rg.name}
                    </DropdownMenu.Item>
                  ))}
              </DropdownMenu.Content>
            </DropdownMenu.Root>
          )}
        </Flex>
        {activeRunGroup && (
          <Link asChild color="blue">
            <RouterLink to={`${isAdminView ? '/admin' : ''}/group/${runGroupId}`}>
              Compliance for <b>{activeRunGroup.name}</b> →
            </RouterLink>
          </Link>
        )}
      </Flex>

      <Separator size="4" mb="3" />

      <Flex gap="3" align="start">
        <Box style={{ width: 400, minWidth: 200, maxHeight: '70vh', overflow: 'auto' }}>
          {summariesQuery.isPending ? (
            <PageSpinner />
          ) : summariesQuery.error ? (
            <ErrorAlert message="Unable to fetch test procedures." />
          ) : (
            <ProcedureList
              summaries={summariesQuery.data}
              selection={selection}
              onSelect={setSelection}
            />
          )}
        </Box>

        <Box style={{ flex: 1 }}>
          <Flex justify="between" align="start" py="1">
            {selection.kind === 'active' ? (
              <Heading as="h4" size="4">
                Active Runs
              </Heading>
            ) : (
              <div>
                <Heading as="h4" size="4">
                  <Link asChild>
                    <RouterLink to={`/procedure/${selection.id}`}>{selection.id}</RouterLink>
                  </Link>
                </Heading>
                <Text as="div" size="2" color="gray" mt="1">
                  {selection.description}
                </Text>
              </div>
            )}
            {selection.kind === 'procedure' && !isAdminView && (
              <Box>
                <Button
                  onClick={() => initMutation.mutate(selection.id)}
                  loading={initMutation.isPending}
                >
                  New Test Run
                </Button>
                <Text as="div" size="1" color="gray" mt="1">
                  May take up to 30s to initialize
                </Text>
              </Box>
            )}
          </Flex>
          <Box style={{ maxHeight: '70vh', overflow: 'auto' }}>
            <RunsTable
              runs={runsQuery.data?.items}
              isPending={runsQuery.isPending}
              error={runsQuery.error}
              isAdminView={isAdminView}
              pendingAction={pendingAction}
              onStart={(runId) => startMutation.mutate(runId)}
              onFinalise={(runId) => finaliseMutation.mutate(runId)}
              onDelete={(runId) => deleteMutation.mutate(runId)}
            />
          </Box>
        </Box>
      </Flex>
    </>
  );
}
