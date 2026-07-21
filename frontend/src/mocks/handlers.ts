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
import complianceRequestsFixture from '../../fixtures/compliance_requests.json';
import adminComplianceRequestsFixture from '../../fixtures/admin_compliance_requests.json';

const session = import.meta.env.VITE_MOCK_ADMIN === 'true' ? sessionAdminFixture : sessionFixture;

// File-producing POST endpoints (cert generation, compliance finalise) — a stub attachment is
// enough; apiDownload only needs a blob and a Content-Disposition filename.
const attachmentResponse = (filename: string, contentType: string) => () =>
  new HttpResponse('stub-file-content', {
    headers: {
      'Content-Type': contentType,
      'Content-Disposition': `attachment; filename=${filename}`,
    },
  });

export const handlers = [
  // ---- Session ----
  http.get('/api/session', () => HttpResponse.json(session)),

  // ---- Config ----
  http.get('/api/config', () => HttpResponse.json(configFixture)),
  http.post('/api/config/pen', () => HttpResponse.json({})),
  http.post('/api/config/domain', () => HttpResponse.json({})),
  http.post(
    '/config/run_group/:runGroupId/cert',
    attachmentResponse('certificate.zip', 'application/zip')
  ),
  http.post('/config/shared_cert', attachmentResponse('certificate.zip', 'application/zip')),

  // ---- Run Groups ----
  http.post('/api/run_groups', () =>
    HttpResponse.json(configFixture.run_groups[0], { status: 201 })
  ),
  http.patch('/api/run_groups/:runGroupId', ({ params }) =>
    HttpResponse.json({ ...configFixture.run_groups[0], run_group_id: Number(params.runGroupId) })
  ),
  http.delete('/api/run_groups/:runGroupId', () => HttpResponse.json({})),
  http.get('/api/run_groups', () => HttpResponse.json(runGroupsFixture)),
  http.get('/api/admin/run_groups', () => HttpResponse.json(runGroupsFixture)),

  // ---- Procedure ----
  http.get('/api/procedure/:testProcedureId', ({ params }) =>
    HttpResponse.json({ ...procedureYamlFixture, test_procedure_id: params.testProcedureId })
  ),

  // ---- Procedures ----
  http.get('/api/procedures', () => HttpResponse.json(proceduresFixture)),

  // ---- Group ----
  http.get('/api/group/:runGroupId/procedure_summaries', () =>
    HttpResponse.json(procedureSummariesFixture)
  ),
  http.get('/api/group/:runGroupId/procedure_runs/:testProcedureId', () =>
    HttpResponse.json(procedureRunsFixture)
  ),
  http.get('/api/group/:runGroupId/active_runs', () => HttpResponse.json(activeRunsFixture)),
  http.get('/api/group/:runGroupId/compliance', () => HttpResponse.json(complianceFixture)),
  http.post('/api/group/:runGroupId/runs', () => HttpResponse.json({ run_id: 991 })),
  http.get('/api/group/:runGroupId/playlist_tests', () => HttpResponse.json(playlistTestsFixture)),
  http.get('/api/group/:runGroupId/playlist_sessions', () =>
    HttpResponse.json(playlistSessionsFixture)
  ),
  http.post('/api/group/:runGroupId/playlist', () => HttpResponse.json({ run_id: 301 })),
  http.get('/api/admin/group/:runGroupId/procedure_summaries', () =>
    HttpResponse.json(procedureSummariesFixture)
  ),
  http.get('/api/admin/group/:runGroupId/procedure_runs/:testProcedureId', () =>
    HttpResponse.json(procedureRunsFixture)
  ),
  http.get('/api/admin/group/:runGroupId/active_runs', () => HttpResponse.json(activeRunsFixture)),
  http.get('/api/admin/group/:runGroupId/compliance', () => HttpResponse.json(complianceFixture)),

  // ---- Runs ----
  http.post('/api/runs/:runId/start', ({ params }) =>
    HttpResponse.json({ run_id: Number(params.runId) })
  ),
  http.post('/api/runs/:runId/finalise', ({ params }) =>
    HttpResponse.json({ run_id: Number(params.runId) })
  ),
  http.delete('/api/runs/:runId', ({ params }) =>
    HttpResponse.json({ run_id: Number(params.runId) })
  ),

  // ---- Run ----
  http.get('/api/run/:runId', () => HttpResponse.json(runStatusShellFixture)),
  http.get('/api/run/:runId/status', () => HttpResponse.json(runStatusRunnerFixture)),
  http.get('/api/run/:runId/requests/:requestId', () =>
    HttpResponse.json(runRequestDetailsFixture)
  ),
  http.get('/api/admin/run/:runId', () => HttpResponse.json(runStatusShellFixture)),
  http.get('/api/admin/run/:runId/status', () => HttpResponse.json(runStatusRunnerFixture)),

  // ---- Runs ----
  http.post('/api/runs/:runId/finalise_playlist', ({ params }) =>
    HttpResponse.json({ run_id: Number(params.runId) })
  ),
  http.post('/api/runs/:runId/proceed', () => HttpResponse.json({ handled: true })),
  http.post('/api/admin/runs/:runId/proceed', () => HttpResponse.json({ handled: true })),

  // ---- Compliance ----
  http.get('/api/compliance/requests', () => HttpResponse.json({requests: complianceRequestsFixture.items})),
  http.get('/api/admin/compliance/requests', () => HttpResponse.json({requests: adminComplianceRequestsFixture.items})),
  http.get('/api/compliance/requests/:complianceRequestId', ({params}) =>
  {
      const result = complianceRequestsFixture.items.filter((r) => `${r.compliance_request_id}` == params.complianceRequestId);
      return result.length > 0 ? HttpResponse.json(result[0]) : new HttpResponse();
  }),
  http.get('/api/compliance/form-data', () =>
    HttpResponse.json({
      csipaus_versions: ["1.2", "1.3"],
      compliance_classes: ["A", "DER-A"],
      tests_by_version_and_class: {"1.2":{"A": ["ALL-01"]}},
      completed_test_procedures: ["ALL-01"],
      successful_runs: [procedureRunsFixture.items[0], procedureRunsFixture.items[1]],
    })
  ),
  // The following puts don't modify any data (since there is no db backing this)
  http.put('/api/compliance/requests/:complianceRequestId', ({ params }) => {
    const result = complianceRequestsFixture.items.filter((r) => `${r.compliance_request_id}` == params.complianceRequestId);
    return result.length > 0 ? HttpResponse.json(result[0]) : new HttpResponse();
  }),
  http.put('/api/admin/compliance/requests/:complianceRequestId', ({ params }) => {
    const result = complianceRequestsFixture.items.filter((r) => `${r.compliance_request_id}` == params.complianceRequestId);
    return result.length > 0 ? HttpResponse.json(result[0]) : new HttpResponse();
  }),
  http.post('/admin/compliance/requests/:requestId/finalise', ({params, request}) => {
    console.log(params);
    console.log(request);
    // return attachmentResponse('compliance.pdf', 'application/pdf')
    return HttpResponse.json({});
  }),
  // TODO
  // http.post('/api/compliance/requests', ({ params }) => HttpResponse.json({ })),
  // http.put('/api/admin/compliance/requests/:complianceRequestId', ({ params }) => HttpResponse.json({ })),
  // http.delete('/api/compliance/requests/:complianceRequestId', ({ params }) => HttpResponse.json({ })),
  // http.delete('/api/admin/compliance/requests/:complianceRequestId', ({ params }) => HttpResponse.json({ })),
  // http.get('/compliance/requests/:complianceRequestId/artifact', () => HttpResponse.json({ })),
  // http.get('/admin/compliance/requests/:complianceRequestId/artifact', () => HttpResponse.json({ })),


  // ---- Admin (other) ----
  http.get('/api/admin/users', () => HttpResponse.json(adminUsersFixture)),
  http.get('/api/admin/stats', () => HttpResponse.json(adminStatsFixture)),

];
