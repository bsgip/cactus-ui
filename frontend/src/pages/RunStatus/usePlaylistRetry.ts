import { useMutation } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { ApiError } from '../../api/client';
import { updatePlaylist } from '../../api/playlists';
import { finaliseRun } from '../../api/runs';
import type { PlaylistRunRow } from './runStatusModel';

interface Args {
  runId: number;
  upcomingRuns: PlaylistRunRow[]; // status === 'initialised', in playlist order
  activeRunId: number | null;
  adminPrefix: string;
  onPlaylistUpdated: () => void;
}

// The two ways to rerun a playlist test: `retry` queues it at the front of the upcoming tail;
// `retryNow` does the same then finalises the active run so the orchestrator hands straight over
// to the fresh attempt (navigating to it). Active/completed entries are never touched.
export function usePlaylistRetry({
  runId,
  upcomingRuns,
  activeRunId,
  adminPrefix,
  onPlaylistUpdated,
}: Args) {
  const navigate = useNavigate();

  const tailWith = (testProcedureId: string) => [
    testProcedureId,
    ...upcomingRuns.map((r) => r.test_procedure_id),
  ];

  const retryMutation = useMutation({
    mutationFn: (testProcedureId: string) =>
      updatePlaylist(runId, tailWith(testProcedureId), activeRunId as number),
    onSuccess: onPlaylistUpdated,
    // On 409 the playlist advanced mid-click; refetching so the badges reflect reality is the
    // right response to any failure.
    onError: () => onPlaylistUpdated(),
  });

  const retryNowMutation = useMutation({
    mutationFn: async (testProcedureId: string) => {
      const updated = await updatePlaylist(runId, tailWith(testProcedureId), activeRunId as number);
      await finaliseRun(activeRunId as number);
      return updated.playlist_runs[0]?.run_id ?? null;
    },
    onSuccess: (nextRunId) => {
      onPlaylistUpdated();
      if (nextRunId != null) {
        void navigate(`${adminPrefix}/run/${nextRunId}`);
      }
    },
    // The tail may have been replaced even if the finalise step failed - refetch either way.
    onError: () => onPlaylistUpdated(),
  });

  const failedMutation = [retryMutation, retryNowMutation].find((m) => m.isError);
  const retryError = !failedMutation
    ? null
    : failedMutation.error instanceof ApiError && failedMutation.error.status === 409
      ? 'The playlist advanced before the retry could be queued - the view has been refreshed. Please try again.'
      : 'Failed to queue the retry. Please try again.';

  return {
    retry: retryMutation.mutate,
    retryNow: retryNowMutation.mutate,
    isRetrying: retryMutation.isPending || retryNowMutation.isPending,
    retryError,
  };
}
