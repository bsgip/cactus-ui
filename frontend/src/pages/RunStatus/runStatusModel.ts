// Client-side presentation models derived from the run-status shell.
//
// The shell forwards canonical cactus-schema types: `shell.run` (the run) and
// `shell.playlist_runs` (the full RunResponse for each run in the playlist — a join the
// orchestrator doesn't do, since RunResponse.playlist_runs only carries summaries). Playlist
// ordering comes from the authoritative summary list (`shell.run.playlist_runs`); per-run
// detail (pass/fail, artifacts) is looked up from `shell.playlist_runs` by id, so the view
// still renders if a detail fetch failed.

import type { RunStatusResponse, RunStatusShell } from '../../api/types';

export interface PlaylistRunRow {
  run_id: number;
  test_procedure_id: string;
  status: RunStatusResponse;
  all_criteria_met: boolean | null;
  has_artifacts: boolean;
}

export interface PlaylistView {
  name: string;
  started_at: string | null;
  runs: PlaylistRunRow[];
  current_order: number | null;
  total: number;
}

export interface CurrentActiveRun {
  run_id: number;
  test_procedure_id: string;
  order: number;
}

const ACTIVE_STATUSES: RunStatusResponse[] = ['started', 'provisioning'];

export function derivePlaylistView(shell: RunStatusShell): PlaylistView | null {
  const summary = shell.run?.playlist_runs;
  if (!summary || summary.length === 0) {
    return null;
  }
  const detailById = new Map((shell.playlist_runs ?? []).map((r) => [r.run_id, r]));
  const runs: PlaylistRunRow[] = summary.map((s) => {
    const detail = detailById.get(s.run_id);
    return {
      run_id: s.run_id,
      test_procedure_id: s.test_procedure_id,
      status: s.status,
      all_criteria_met: detail ? detail.all_criteria_met : null,
      has_artifacts: detail ? detail.has_artifacts : false,
    };
  });
  return {
    name: shell.playlist_name ?? 'Playlist',
    started_at: detailById.get(summary[0].run_id)?.created_at ?? null,
    runs,
    current_order: shell.run?.playlist_order ?? null,
    total: summary.length,
  };
}

export function deriveCurrentActiveRun(shell: RunStatusShell): CurrentActiveRun | null {
  const summary = shell.run?.playlist_runs;
  if (!summary) {
    return null;
  }
  const order = summary.findIndex((r) => ACTIVE_STATUSES.includes(r.status));
  if (order === -1) {
    return null;
  }
  const run = summary[order];
  return { run_id: run.run_id, test_procedure_id: run.test_procedure_id, order };
}

export function deriveNextPlaylistRunId(shell: RunStatusShell): number | null {
  const summary = shell.run?.playlist_runs;
  const order = shell.run?.playlist_order;
  if (!summary || order == null) {
    return null;
  }
  return order + 1 < summary.length ? summary[order + 1].run_id : null;
}
