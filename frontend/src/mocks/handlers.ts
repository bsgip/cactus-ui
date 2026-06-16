import { http, HttpResponse } from 'msw';
import activeRunsFixture from '../../fixtures/active_runs.json';
import complianceFixture from '../../fixtures/compliance.json';
import procedureRunsFixture from '../../fixtures/procedure_runs.json';
import procedureSummariesFixture from '../../fixtures/procedure_summaries.json';
import procedureYamlFixture from '../../fixtures/procedure_yaml.json';
import proceduresFixture from '../../fixtures/procedures.json';
import runGroupsFixture from '../../fixtures/run_groups.json';
import sessionFixture from '../../fixtures/session.json';

export const handlers = [
  http.get('/api/session', () => HttpResponse.json(sessionFixture)),
  http.get('/api/procedures', () => HttpResponse.json(proceduresFixture)),
  http.get('/api/procedure/:testProcedureId', ({ params }) =>
    HttpResponse.json({ ...procedureYamlFixture, test_procedure_id: params.testProcedureId })
  ),
  http.get('/api/run_groups', () => HttpResponse.json(runGroupsFixture)),
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
];
