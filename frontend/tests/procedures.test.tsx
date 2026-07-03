import { screen, within } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';
import proceduresFixture from '../fixtures/procedures.json';
import { server } from './msw-server';
import { renderApp } from './test-utils';

describe('procedures page', () => {
  it('renders the procedures table from the fixture', async () => {
    renderApp('/procedures');

    expect(await screen.findByRole('heading', { name: 'Test Procedures' })).toBeInTheDocument();
    expect(document.title).toBe('Procedures - CACTUS');

    expect(
      await screen.findByRole('columnheader', { name: 'Test Procedure ID' })
    ).toBeInTheDocument();
    for (const header of ['Description', 'Category']) {
      expect(screen.getByRole('columnheader', { name: header })).toBeInTheDocument();
    }

    // One row per fixture procedure (plus the header row)
    expect(screen.getAllByRole('row')).toHaveLength(proceduresFixture.procedures.length + 1);

    // Spot-check the first procedure: id links to the YAML page
    const first = proceduresFixture.procedures[0];
    const link = screen.getByRole('link', { name: first.test_procedure_id });
    expect(link).toHaveAttribute('href', `/procedure/${first.test_procedure_id}`);
    const row = link.closest('tr')!;
    expect(within(row).getByText(first.description)).toBeInTheDocument();
    expect(within(row).getByText(first.category)).toBeInTheDocument();
  });

  it('shows the empty state when there are no procedures', async () => {
    server.use(http.get('/api/procedures', () => HttpResponse.json({ procedures: [] })));
    renderApp('/procedures');

    expect(await screen.findByText('No procedures available.')).toBeInTheDocument();
  });

  it('shows the error alert when the fetch fails', async () => {
    server.use(
      http.get('/api/procedures', () =>
        HttpResponse.json({ error: 'Failed to retrieve procedures.' }, { status: 502 })
      )
    );
    renderApp('/procedures');

    expect(await screen.findByText('Failed to retrieve procedures.')).toBeInTheDocument();
  });

  // Client-side navigation via the NavBar <Link> is covered by the Playwright spec;
  // here we just pin the link target.
  it('is linked from the NavBar', async () => {
    renderApp('/');

    expect(await screen.findByRole('link', { name: 'Procedures' })).toHaveAttribute(
      'href',
      '/procedures'
    );
  });
});
