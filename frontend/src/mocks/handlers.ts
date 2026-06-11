import { http, HttpResponse } from 'msw';
import sessionFixture from '../../fixtures/session.json';

export const handlers = [http.get('/api/session', () => HttpResponse.json(sessionFixture))];
