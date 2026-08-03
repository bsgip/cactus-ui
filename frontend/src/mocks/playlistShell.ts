import runStatusShellPlaylistFixture from '../../fixtures/run_status_shell_playlist.json';

// Mutable copy of the playlist shell so playlist edits/retries/finalises made in mock mode stick
// across refetches. The templates keep the original fixture's queued-run shape for added tests.
const playlistShell = structuredClone(runStatusShellPlaylistFixture);
const upcomingRunTemplate = runStatusShellPlaylistFixture.playlist_runs[2];
const upcomingSummaryTemplate = runStatusShellPlaylistFixture.run.playlist_runs[2];

const syncPlaylistSummary = () => {
  playlistShell.run.playlist_runs = playlistShell.playlist_runs.map(
    ({ run_id, test_procedure_id, status }) => ({ run_id, test_procedure_id, status })
  );
};

// Compose the shell for one run of the mock playlist, so navigating between playlist runs works.
export const playlistShellForRun = (runId: number) => {
  const index = playlistShell.playlist_runs.findIndex((r) => r.run_id === runId);
  if (index === -1) {
    return playlistShell;
  }
  const row = playlistShell.playlist_runs[index];
  return {
    ...playlistShell,
    run: {
      ...playlistShell.run,
      ...row,
      playlist_order: index,
      playlist_runs: playlistShell.run.playlist_runs,
    },
    run_is_live: row.status === 'started' || row.status === 'provisioning',
  };
};

// Finalising a mock playlist run records it and hands over to the next queued test.
export const finaliseMockPlaylistRun = (runId: number) => {
  const row = playlistShell.playlist_runs.find((r) => r.run_id === runId);
  if (!row) {
    return;
  }
  row.status = 'finalised';
  row.all_criteria_met = row.all_criteria_met ?? false;
  row.finalised_at = new Date().toISOString();
  const next = playlistShell.playlist_runs.find((r) => r.status === 'initialised');
  if (next) {
    next.status = 'started';
  }
  syncPlaylistSummary();
};

// Replace the upcoming tail in the mock shell so the banner shows the edit on refetch. Returns
// the new tail in playlist-summary shape (the update endpoint's response body).
export const replaceMockPlaylistTail = (testProcedureIds: string[]) => {
  const summaryTail = testProcedureIds.map((test_procedure_id, i) => ({
    ...upcomingSummaryTemplate,
    run_id: 900 + i,
    test_procedure_id,
  }));
  playlistShell.playlist_runs = [
    ...playlistShell.playlist_runs.filter((r) => r.status !== 'initialised'),
    ...summaryTail.map((s) => ({
      ...upcomingRunTemplate,
      run_id: s.run_id,
      test_procedure_id: s.test_procedure_id,
      test_url: `https://cactus.example/run/${s.run_id}`,
    })),
  ];
  syncPlaylistSummary();
  return summaryTail;
};
