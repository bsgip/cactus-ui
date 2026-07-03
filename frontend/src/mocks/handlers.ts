import { http, HttpResponse } from 'msw';
import activeRunsFixture from '../../fixtures/active_runs.json';
import adminStatsFixture from '../../fixtures/admin_stats.json';
import adminUsersFixture from '../../fixtures/admin_users.json';
import complianceFixture from '../../fixtures/compliance.json';
import configFixture from '../../fixtures/config.json';
import playlistSessionsFixture from '../../fixtures/playlist_sessions.json';
import playlistTestsFixture from '../../fixtures/playlist_tests.json';
import procedureRunsFixture from '../../fixtures/procedure_runs.json';
import procedureSummariesFixture from '../../fixtures/procedure_summaries.json';
import procedureYamlFixture from '../../fixtures/procedure_yaml.json';
import proceduresFixture from '../../fixtures/procedures.json';
import runGroupsFixture from '../../fixtures/run_groups.json';
import runRequestDetailsFixture from '../../fixtures/run_request_details.json';
import runStatusRunnerFixture from '../../fixtures/run_status_runner.json';
import runStatusShellFixture from '../../fixtures/run_status_shell.json';
import sessionFixture from '../../fixtures/session.json';
import sessionAdminFixture from '../../fixtures/session_admin.json';

const session = import.meta.env.VITE_MOCK_ADMIN === 'true' ? sessionAdminFixture : sessionFixture;

export const handlers = [
  http.get('/api/session', () => HttpResponse.json(session)),
  http.get('/api/config', () => HttpResponse.json(configFixture)),
  http.post('/api/config/pen', () => HttpResponse.json({})),
  http.post('/api/config/domain', () => HttpResponse.json({})),
  http.post('/api/run_groups', () =>
    HttpResponse.json(configFixture.run_groups[0], { status: 201 })
  ),
  http.patch('/api/run_groups/:runGroupId', ({ params }) =>
    HttpResponse.json({ ...configFixture.run_groups[0], run_group_id: Number(params.runGroupId) })
  ),
  http.delete('/api/run_groups/:runGroupId', () => HttpResponse.json({})),
  http.get('/api/procedures', () => HttpResponse.json(proceduresFixture)),
  http.get('/api/procedure/:testProcedureId', ({ params }) =>
    HttpResponse.json({ ...procedureYamlFixture, test_procedure_id: params.testProcedureId })
  ),
  http.get('/api/run_groups', () => HttpResponse.json(runGroupsFixture)),
  http.get('/api/admin/users', () => HttpResponse.json(adminUsersFixture)),
  http.get('/api/admin/stats', () => HttpResponse.json(adminStatsFixture)),
  http.get('/api/admin/run_groups', () => HttpResponse.json(runGroupsFixture)),
  http.get('/api/group/:runGroupId/procedure_summaries', () =>
    HttpResponse.json(procedureSummariesFixture)
  ),
  http.get('/api/admin/group/:runGroupId/procedure_summaries', () =>
    HttpResponse.json(procedureSummariesFixture)
  ),
  // The fixture holds ALL-01 runs; close enough for any requested procedure.
  http.get('/api/group/:runGroupId/procedure_runs/:testProcedureId', () =>
    HttpResponse.json(procedureRunsFixture)
  ),
  http.get('/api/admin/group/:runGroupId/procedure_runs/:testProcedureId', () =>
    HttpResponse.json(procedureRunsFixture)
  ),
  http.get('/api/group/:runGroupId/active_runs', () => HttpResponse.json(activeRunsFixture)),
  http.get('/api/admin/group/:runGroupId/active_runs', () => HttpResponse.json(activeRunsFixture)),
  http.get('/api/group/:runGroupId/compliance', () => HttpResponse.json(complianceFixture)),
  http.get('/api/admin/group/:runGroupId/compliance', () => HttpResponse.json(complianceFixture)),
  http.post('/api/group/:runGroupId/runs', () => HttpResponse.json({ run_id: 991 })),
  http.post('/api/runs/:runId/start', ({ params }) =>
    HttpResponse.json({ run_id: Number(params.runId) })
  ),
  http.post('/api/runs/:runId/finalise', ({ params }) =>
    HttpResponse.json({ run_id: Number(params.runId) })
  ),
  http.delete('/api/runs/:runId', ({ params }) =>
    HttpResponse.json({ run_id: Number(params.runId) })
  ),
  http.get('/api/group/:runGroupId/playlist_tests', () => HttpResponse.json(playlistTestsFixture)),
  http.get('/api/group/:runGroupId/playlist_sessions', () =>
    HttpResponse.json(playlistSessionsFixture)
  ),
  http.post('/api/group/:runGroupId/playlist', () => HttpResponse.json({ run_id: 301 })),
  http.post('/api/runs/:runId/finalise_playlist', ({ params }) =>
    HttpResponse.json({ run_id: Number(params.runId) })
  ),
  // Run status page. The shell defaults to a live standalone run; tests override with
  // server.use() for the finalised / playlist / not-found variants.
  http.get('/api/run/:runId', () => HttpResponse.json(runStatusShellFixture)),
  http.get('/api/admin/run/:runId', () => HttpResponse.json(runStatusShellFixture)),
  http.get('/api/run/:runId/status', () => HttpResponse.json(runStatusRunnerFixture)),
  http.get('/api/admin/run/:runId/status', () => HttpResponse.json(runStatusRunnerFixture)),
  http.get('/api/run/:runId/requests/:requestId', () =>
    HttpResponse.json(runRequestDetailsFixture)
  ),
  http.post('/api/runs/:runId/proceed', () => HttpResponse.json({ handled: true })),
  http.post('/api/admin/runs/:runId/proceed', () => HttpResponse.json({ handled: true })),
  http.get('/api/compliance/requests', () => HttpResponse.json({ requests: [] })),
  http.get('/api/admin/compliance/requests', () => HttpResponse.json({ requests: [] })),
  http.get('/api/compliance/form-data', () =>
    HttpResponse.json({
      csipaus_versions: [],
      compliance_classes: [],
      tests_by_version_and_class: {},
      completed_test_procedures: [],
      successful_runs: [],
    })
  ),
];
