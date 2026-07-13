import { Flex, Spinner } from '@radix-ui/themes';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { ApiError } from '../../api/client';
import { fetchRunnerStatus, fetchRunStatusShell } from '../../api/runStatus';
import { finalisePlaylist } from '../../api/playlists';
import { finaliseRun, startRun } from '../../api/runs';
import { Banner } from '../../components/Banner';
import { ErrorAlert } from '../../components/ErrorAlert';
import { PageSpinner } from '../../components/PageSpinner';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import { useSession } from '../../hooks/useSession';
import { FinalisedView } from './FinalisedView';
import { LiveHeaderCard } from './LiveHeaderCard';
import { LiveStatusPanels } from './LiveStatusPanels';
import { NotYetActiveAlert } from './NotYetActiveAlert';
import { PlaylistBanner } from './PlaylistBanner';
import {
  deriveCurrentActiveRun,
  deriveNextPlaylistRunId,
  derivePlaylistView,
} from './runStatusModel';
import { StatusBanner } from './StatusBanner';

const POLL_INTERVAL_MS = 10_000;

// One component for both the user and admin views: isAdminView selects /api vs /api/admin
// paths and gates the lifecycle controls (Start/Finalise are disabled in the admin view).
export function RunStatusPage({ isAdminView }: { isAdminView: boolean }) {
  const { runId: runIdParam } = useParams();
  const runId = Number(runIdParam);
  useDocumentTitle(`Run Status ${runId} - CACTUS`);
  const navigate = useNavigate();
  const adminPrefix = isAdminView ? '/admin' : '';
  const queryClient = useQueryClient();
  const { data: session } = useSession();
  const [actionError, setActionError] = useState<string | null>(null);

  const shellQuery = useQuery({
    queryKey: ['run_status_shell', runId, isAdminView],
    queryFn: () => fetchRunStatusShell(runId, isAdminView),
  });

  const invalidateShell = () =>
    queryClient.invalidateQueries({ queryKey: ['run_status_shell', runId, isAdminView] });

  // Polled RunnerStatus, only while the run is live. Stops polling once the runner is gone (410).
  const statusQuery = useQuery({
    queryKey: ['run_status_runner', runId, isAdminView],
    queryFn: () => fetchRunnerStatus(runId, isAdminView),
    enabled: shellQuery.data?.run_is_live === true,
    retry: false,
    refetchInterval: (query) =>
      query.state.error instanceof ApiError && query.state.error.status === 410
        ? false
        : POLL_INTERVAL_MS,
  });

  // When the runner terminates (410) the run has finalised — refetch the shell so the page
  // flips to the finalised view.
  const statusError = statusQuery.error;
  useEffect(() => {
    if (statusError instanceof ApiError && statusError.status === 410) {
      void queryClient.invalidateQueries({ queryKey: ['run_status_shell', runId, isAdminView] });
    }
  }, [statusError, queryClient, runId, isAdminView]);

  const onActionError = (error: Error) => setActionError(error.message);

  const startMutation = useMutation({
    mutationFn: () => startRun(runId),
    onSuccess: () => void invalidateShell(),
    onError: onActionError,
  });

  // Finalise hands over to the next playlist run if there is one, otherwise refetches the
  // shell so the page flips to the finalised view.
  const finaliseMutation = useMutation({
    mutationFn: () => finaliseRun(runId),
    onSuccess: () => {
      const next = shellQuery.data ? deriveNextPlaylistRunId(shellQuery.data) : null;
      if (next) {
        void navigate(`${adminPrefix}/run/${next}`);
      } else {
        void invalidateShell();
      }
    },
    onError: onActionError,
  });

  // End Playlist finalises the current run and skips the rest, then returns to /playlists.
  // Pure mutation — the ZIP download lives on the Past Sessions list.
  const endPlaylistMutation = useMutation({
    mutationFn: () => finalisePlaylist(runId),
    onSuccess: () => void navigate('/playlists'),
    onError: onActionError,
  });

  if (shellQuery.isPending) {
    return <PageSpinner />;
  }
  if (shellQuery.error || !shellQuery.data) {
    return <ErrorAlert message="Unable to load run status." />;
  }

  const shell = shellQuery.data;
  const run = shell.run;
  const runStatus = run?.status ?? null;
  const playlistView = derivePlaylistView(shell);
  const currentActiveRun = deriveCurrentActiveRun(shell);
  const nextPlaylistRunId = deriveNextPlaylistRunId(shell);
  const showNotYetActive =
    currentActiveRun != null && runStatus === 'initialised' && currentActiveRun.run_id !== runId;

  return (
    <Flex direction="column" gap="3" style={{ maxWidth: 1000, margin: '0 auto' }}>
      <Banner message={session?.banner_message} />
      {actionError && <ErrorAlert message={actionError} />}

      {playlistView && (
        <PlaylistBanner
          playlistView={playlistView}
          currentActiveRun={currentActiveRun}
          runId={runId}
          runProcedureId={run?.test_procedure_id ?? null}
          isAdminView={isAdminView}
          isEnding={endPlaylistMutation.isPending}
          onEndPlaylist={() => endPlaylistMutation.mutate()}
        />
      )}

      {showNotYetActive && currentActiveRun && (
        <NotYetActiveAlert
          currentActiveRun={currentActiveRun}
          total={playlistView?.total ?? 0}
          isAdminView={isAdminView}
        />
      )}

      {shell.run_is_live ? (
        <>
          <LiveHeaderCard
            runId={runId}
            runStatus={runStatus}
            runTestUri={run?.test_url ?? null}
            instructions={statusQuery.data?.instructions ?? []}
            isAdminView={isAdminView}
            isStarting={startMutation.isPending}
            isFinalising={finaliseMutation.isPending}
            onStart={() => startMutation.mutate()}
            onFinalise={() => finaliseMutation.mutate()}
          />

          {statusQuery.data ? (
            <LiveStatusPanels
              status={statusQuery.data}
              runId={runId}
              runStatus={runStatus}
              runProcedureId={run?.test_procedure_id ?? null}
              isAdminView={isAdminView}
            />
          ) : statusError && !(statusError instanceof ApiError && statusError.status === 410) ? (
            <ErrorAlert message="Failed to retrieve current status." />
          ) : (
            <Flex justify="center" py="6">
              <Spinner size="3" />
            </Flex>
          )}

          {/* Spacer so the fixed bottom banner never overlaps the last card. */}
          <div style={{ height: 60 }} />
          <StatusBanner stepStatus={statusQuery.data?.step_status ?? null} />
        </>
      ) : (
        <FinalisedView
          runId={runId}
          runStatus={runStatus}
          runHasArtifacts={run?.has_artifacts ?? null}
          isImmediateStart={run?.immediate_start ?? false}
          nextPlaylistRunId={nextPlaylistRunId}
          supportEmail={session?.support_email}
          isAdminView={isAdminView}
        />
      )}
    </Flex>
  );
}
