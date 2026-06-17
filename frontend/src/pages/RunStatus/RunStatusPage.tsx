import { Center, Loader, Stack } from '@mantine/core';
import { useDocumentTitle } from '@mantine/hooks';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { ApiError } from '../../api/client';
import { fetchRunnerStatus, fetchRunStatusShell } from '../../api/runStatus';
import { finalisePlaylist } from '../../api/playlists';
import { finaliseRun, startRun } from '../../api/runs';
import { Banner } from '../../components/Banner';
import { ErrorAlert } from '../../components/ErrorAlert';
import { PageSpinner } from '../../components/PageSpinner';
import { useSession } from '../../hooks/useSession';
import { FinalisedView } from './FinalisedView';
import { LiveHeaderCard } from './LiveHeaderCard';
import { LiveStatusPanels } from './LiveStatusPanels';
import { NotYetActiveAlert } from './NotYetActiveAlert';
import { PlaylistBanner } from './PlaylistBanner';
import { StatusBanner } from './StatusBanner';

const POLL_INTERVAL_MS = 10_000;

// Port of run_status.html / run_status_page + admin_run_status_page. One component for
// both views: isAdminView selects /api vs /api/admin paths and gates the lifecycle
// controls (Start/Finalise are admin-disabled, mirroring the old user_buttons_state).
//
// 9b scope: page chrome — playlist banner, not-yet-active warning, live header card, and
// the non-live (Not Found / Skipped / Finalised) view. The live status panels and the
// timeline charts are added in 9c/9d.
export function RunStatusPage({ isAdminView }: { isAdminView: boolean }) {
  const { runId: runIdParam } = useParams();
  const runId = Number(runIdParam);
  useDocumentTitle(`Run Status ${runId} - CACTUS`);
  const queryClient = useQueryClient();
  const { data: session } = useSession();
  const [actionError, setActionError] = useState<string | null>(null);

  const shellQuery = useQuery({
    queryKey: ['run_status_shell', runId, isAdminView],
    queryFn: () => fetchRunStatusShell(runId, isAdminView),
  });

  const invalidateShell = () =>
    queryClient.invalidateQueries({ queryKey: ['run_status_shell', runId, isAdminView] });

  // Polled RunnerStatus, only while the run is live. Stops polling once the runner is gone
  // (410), mirroring the old page's "reload on HTTP GONE" behaviour.
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
  // shell so the page flips to the finalised view (the live status query 410s in 9c).
  const finaliseMutation = useMutation({
    mutationFn: () => finaliseRun(runId),
    onSuccess: () => {
      const next = shellQuery.data?.next_playlist_run_id;
      if (next) {
        window.location.assign(`/run/${next}`);
      } else {
        void invalidateShell();
      }
    },
    onError: onActionError,
  });

  // End Playlist finalises the current run and skips the rest, then returns to /playlists.
  // Pure mutation — the ZIP download lives on the Past Sessions list (page 8 decision).
  const endPlaylistMutation = useMutation({
    mutationFn: () => finalisePlaylist(runId),
    onSuccess: () => window.location.assign('/playlists'),
    onError: onActionError,
  });

  if (shellQuery.isPending) {
    return <PageSpinner />;
  }
  if (shellQuery.error || !shellQuery.data) {
    return <ErrorAlert message="Unable to load run status." />;
  }

  const shell = shellQuery.data;
  const showNotYetActive =
    shell.current_active_run != null &&
    shell.run_status === 'initialised' &&
    shell.current_active_run.run_id !== shell.run_id;

  return (
    <Stack maw={1000} mx="auto">
      <Banner message={session?.banner_message} />
      {actionError && <ErrorAlert message={actionError} />}

      {shell.playlist_info && (
        <PlaylistBanner
          playlistInfo={shell.playlist_info}
          currentActiveRun={shell.current_active_run}
          runId={shell.run_id}
          runProcedureId={shell.run_procedure_id}
          isAdminView={isAdminView}
          isEnding={endPlaylistMutation.isPending}
          onEndPlaylist={() => endPlaylistMutation.mutate()}
        />
      )}

      {showNotYetActive && shell.current_active_run && (
        <NotYetActiveAlert
          currentActiveRun={shell.current_active_run}
          total={shell.playlist_info?.total ?? 0}
          isAdminView={isAdminView}
        />
      )}

      {shell.run_is_live ? (
        <>
          <LiveHeaderCard
            runId={shell.run_id}
            runStatus={shell.run_status}
            runTestUri={shell.run_test_uri}
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
              runId={shell.run_id}
              runStatus={shell.run_status}
              runProcedureId={shell.run_procedure_id}
              isAdminView={isAdminView}
            />
          ) : statusError && !(statusError instanceof ApiError && statusError.status === 410) ? (
            <ErrorAlert message="Failed to retrieve current status." />
          ) : (
            <Center py="xl">
              <Loader color="green" />
            </Center>
          )}

          {/* Spacer so the fixed bottom banner never overlaps the last card. */}
          <div style={{ height: 60 }} />
          <StatusBanner stepStatus={statusQuery.data?.step_status ?? null} />
        </>
      ) : (
        <FinalisedView
          shell={shell}
          supportEmail={session?.support_email}
          isAdminView={isAdminView}
        />
      )}
    </Stack>
  );
}
