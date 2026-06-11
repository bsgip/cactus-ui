import { http, HttpResponse } from 'msw';
import procedureYamlFixture from '../../fixtures/procedure_yaml.json';
import proceduresFixture from '../../fixtures/procedures.json';
import sessionFixture from '../../fixtures/session.json';

export const handlers = [
  http.get('/api/session', () => HttpResponse.json(sessionFixture)),
  http.get('/api/procedures', () => HttpResponse.json(proceduresFixture)),
  http.get('/api/procedure/:testProcedureId', ({ params }) =>
    HttpResponse.json({ ...procedureYamlFixture, test_procedure_id: params.testProcedureId })
  ),
];
