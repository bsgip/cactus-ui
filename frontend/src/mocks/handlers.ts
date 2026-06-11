import { http, HttpResponse } from 'msw';
import proceduresFixture from '../../fixtures/procedures.json';
import sessionFixture from '../../fixtures/session.json';

export const handlers = [
  http.get('/api/session', () => HttpResponse.json(sessionFixture)),
  http.get('/api/procedures', () => HttpResponse.json(proceduresFixture)),
];
