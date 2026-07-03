import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';
import activeRunsFixture from '../fixtures/active_runs.json';
import procedureRunsFixture from '../fixtures/procedure_runs.json';
import { server } from './msw-server';
import { renderApp } from './test-utils';

const emptyPage = {
  total_pages: 1,
  total_items: 0,
  page_size: 100,
  current_page: 1,
  prev_page: null,
  next_page: null,
  items: [],
};

describe('runs page', () => {
  it('shows active runs by default with the run group header', async () => {
    renderApp('/group/1/runs');

    expect(await screen.findByRole('heading', { name: 'Runs for' })).toBeInTheDocument();
    expect(document.title).toBe('Runs - CACTUS');

    // Two run groups in the fixture -> the active group renders as a dropdown button
    expect(await screen.findByRole('button', { name: 'Battery Mk1' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Active Runs' })).toBeInTheDocument();

    // Active runs from the fixture, linking to the (Flask) run status page
    const run = activeRunsFixture.items[0];
    const link = await screen.findByRole('link', { name: String(run.run_id) });
    expect(link).toHaveAttribute('href', `/run/${run.run_id}`);
    expect(within(link.closest('tr')!).getByText(run.status)).toBeInTheDocument();

    // The compliance summary link goes to the React run group page
    expect(screen.getByRole('link', { name: /Compliance for/ })).toHaveAttribute(
      'href',
      '/group/1'
    );
  });

  it('switches run groups through the dropdown', async () => {
    const user = userEvent.setup();
    const { router } = renderApp('/group/1/runs');

    await user.click(await screen.findByRole('button', { name: 'Battery Mk1' }));
    await user.click(await screen.findByRole('menuitem', { name: 'Battery Mk2' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/group/2/runs'));
  });

  it('lists procedures by category with run-count badges and loads runs on selection', async () => {
    const user = userEvent.setup();
    renderApp('/group/1/runs');

    // Category headers from the fixture (native <details>/<summary> accordion)
    expect(await screen.findByText('Registration')).toBeInTheDocument();

    // ALL-01 has 3 runs, latest passing -> badge shows the count
    const all01 = await screen.findByRole('button', { name: /ALL-01/ });
    expect(within(all01).getByText('3')).toBeInTheDocument();

    await user.click(all01);

    // Title becomes a link to the procedure page plus its description
    const titleLink = await screen.findByRole('link', { name: 'ALL-01' });
    expect(titleLink).toHaveAttribute('href', '/procedure/ALL-01');
    expect(screen.getByRole('button', { name: 'New Test Run' })).toBeInTheDocument();
    expect(screen.getByText('May take up to 30s to initialize')).toBeInTheDocument();

    // Runs from the procedure_runs fixture: finalised-with-artifacts gets Download,
    // initialised gets Start, and every row gets a Delete control in the user view
    const downloadButtons = await screen.findAllByRole('link', { name: 'Download' });
    expect(downloadButtons[0]).toHaveAttribute('href', '/run/120/artifact');
    expect(screen.getByRole('button', { name: 'Start' })).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: /Delete run/ })).toHaveLength(
      procedureRunsFixture.items.length
    );
  });

  it('filters procedures by compliance class', async () => {
    const user = userEvent.setup();
    renderApp('/group/1/runs');

    expect(await screen.findByText('Showing ALL compliance classes')).toBeInTheDocument();

    // The filter dialog aria-hides the page behind it, so close it before asserting on the
    // procedure list (role queries skip elements hidden from the accessibility tree).
    await user.click(screen.getByRole('button', { name: 'Filter compliance classes' }));
    const modal = await screen.findByRole('dialog');
    await user.click(within(modal).getByRole('button', { name: 'Select NONE' }));
    await user.click(within(modal).getByRole('button', { name: 'Close' }));

    expect(await screen.findByText('Showing NO compliance classes')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /ALL-01/ })).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Filter compliance classes' }));
    const modal2 = await screen.findByRole('dialog');
    await user.click(within(modal2).getByRole('button', { name: 'Select ALL' }));
    await user.click(within(modal2).getByRole('button', { name: 'Close' }));

    expect(await screen.findByText('Showing ALL compliance classes')).toBeInTheDocument();
    expect(await screen.findByRole('button', { name: /ALL-01/ })).toBeInTheDocument();
  });

  it('disables run lifecycle controls in the admin view', async () => {
    const user = userEvent.setup();
    renderApp('/admin/group/1/runs');

    // Active runs: admins see the status-appropriate action buttons, but disabled
    // (started -> Finalise, initialised -> Start)
    expect(await screen.findByRole('button', { name: 'Finalise' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Start' })).toBeDisabled();
    expect(screen.queryByRole('button', { name: /Delete run/ })).not.toBeInTheDocument();

    // Admin run links target the admin run status page
    expect(screen.getByRole('link', { name: '123' })).toHaveAttribute('href', '/admin/run/123');

    // Selecting a procedure: New Test Run is shown but disabled, Download uses the
    // admin artifact route
    await user.click(await screen.findByRole('button', { name: /ALL-01/ }));
    const downloadButtons = await screen.findAllByRole('link', { name: 'Download' });
    expect(downloadButtons[0]).toHaveAttribute('href', '/admin/run/120/artifact');
    expect(screen.getByRole('button', { name: 'New Test Run' })).toBeDisabled();
  });

  it('shows the empty state when no runs are returned', async () => {
    server.use(http.get('/api/group/:id/active_runs', () => HttpResponse.json(emptyPage)));
    renderApp('/group/1/runs');

    expect(await screen.findByText('No runs were returned.')).toBeInTheDocument();
  });

  it('shows error states for failed fetches', async () => {
    server.use(
      http.get('/api/group/:id/active_runs', () =>
        HttpResponse.json({ error: 'Unable to load active runs.' }, { status: 502 })
      ),
      http.get('/api/group/:id/procedure_summaries', () =>
        HttpResponse.json({ error: 'Unable to fetch test procedures.' }, { status: 502 })
      ),
      http.get('/api/run_groups', () =>
        HttpResponse.json({ error: 'Unable to fetch run groups.' }, { status: 502 })
      )
    );
    renderApp('/group/1/runs');

    expect(await screen.findByText('Unable to load active runs.')).toBeInTheDocument();
    expect(await screen.findByText('Unable to fetch test procedures.')).toBeInTheDocument();
    expect(await screen.findByText('Unable to fetch run groups.')).toBeInTheDocument();
  });

  it('deletes a run via the API', async () => {
    const user = userEvent.setup();
    let deletedRunId: number | null = null;
    server.use(
      http.delete('/api/runs/:runId', ({ params }) => {
        deletedRunId = Number(params.runId);
        return HttpResponse.json({ run_id: deletedRunId });
      })
    );
    renderApp('/group/1/runs');

    await user.click(await screen.findByRole('button', { name: 'Delete run 123' }));

    await waitFor(() => expect(deletedRunId).toBe(123));
  });

  it('shows the action error when a mutation fails', async () => {
    const user = userEvent.setup();
    server.use(
      http.delete('/api/runs/:runId', () =>
        HttpResponse.json({ error: 'Failed to delete run.' }, { status: 502 })
      )
    );
    renderApp('/group/1/runs');

    await user.click(await screen.findByRole('button', { name: 'Delete run 123' }));

    expect(await screen.findByText('Failed to delete run.')).toBeInTheDocument();
  });
});

describe('run start/initialise navigation', () => {
  it('navigates to the run status page after starting a run', async () => {
    const user = userEvent.setup();
    const { router } = renderApp('/group/1/runs');

    await user.click(await screen.findByRole('button', { name: /ALL-01/ }));
    await user.click(await screen.findByRole('button', { name: 'Start' }));

    await waitFor(() => expect(router.state.location.pathname).toBe('/run/110'));
  });

  it('navigates to the new run after initialising', async () => {
    const user = userEvent.setup();
    const { router } = renderApp('/group/1/runs');

    await user.click(await screen.findByRole('button', { name: /ALL-01/ }));
    await user.click(await screen.findByRole('button', { name: 'New Test Run' }));

    await waitFor(() => expect(router.state.location.pathname).toBe('/run/991'));
  });
});

describe('/runs redirect', () => {
  // The redirect itself (client-side navigate to the first group) can't run under
  // jsdom + MSW (undici Request interception clash) — covered by the Playwright spec.

  it('is linked from the NavBar', async () => {
    renderApp('/');

    expect(await screen.findByRole('link', { name: 'Runs' })).toHaveAttribute('href', '/runs');
  });

  it('shows an error when run groups cannot be fetched', async () => {
    server.use(
      http.get('/api/run_groups', () =>
        HttpResponse.json({ error: 'Unable to fetch run groups.' }, { status: 502 })
      )
    );
    renderApp('/runs');

    expect(await screen.findByText('Unable to fetch run groups.')).toBeInTheDocument();
  });
});
