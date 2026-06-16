import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';
import { server } from './msw-server';
import { renderApp } from './test-utils';

describe('run group compliance page', () => {
  it('shows heading with group name and compliance table', async () => {
    renderApp('/group/1');

    expect(await screen.findByRole('heading', { name: 'Compliance for' })).toBeInTheDocument();
    expect(document.title).toBe('Compliance - CACTUS');

    // Two groups in fixture -> renders as dropdown button
    expect(await screen.findByRole('button', { name: 'Battery Mk1' })).toBeInTheDocument();

    // Table header
    expect(screen.getByRole('columnheader', { name: 'Class' })).toBeInTheDocument();
    expect(screen.getByRole('columnheader', { name: 'Latest Runs' })).toBeInTheDocument();

    // Class A row from fixture
    expect(screen.getByRole('cell', { name: 'A' })).toBeInTheDocument();
    expect(
      screen.getByRole('cell', {
        name: 'All clients managing DER (Excluding demand response).',
      })
    ).toBeInTheDocument();
  });

  it('renders success, failed, and runless badges correctly', async () => {
    renderApp('/group/1');

    // ALL-01 is success in class A (also appears in DR-A -> multiple links with same name)
    const successBadges = await screen.findAllByRole('link', { name: /ALL-01/ });
    expect(successBadges[0]).toHaveAttribute('href', '/run/120');

    // ALL-02 is failed -> has a link to run status (unique in the fixture)
    const failedBadge = await screen.findByRole('link', { name: /ALL-02/ });
    expect(failedBadge).toHaveAttribute('href', '/run/118');

    // ALL-03-REJ is runless -> plain badge (no link)
    expect(screen.getByText('ALL-03-REJ')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /ALL-03-REJ/ })).not.toBeInTheDocument();
  });

  it('active badge renders with a link', async () => {
    // Override compliance with an active-status procedure
    server.use(
      http.get('/api/group/:runGroupId/compliance', () =>
        HttpResponse.json({
          compliance_by_class: [
            {
              class_name: 'C',
              class_details: { name: 'C', description: 'ConnectionPoint clients.' },
              compliant: false,
              per_run_status: [
                {
                  test_procedure_id: 'ALL-03',
                  description: 'Connection Point registration',
                  latest_run_id: 123,
                  status: 'active',
                },
              ],
            },
          ],
        })
      )
    );

    renderApp('/group/1');

    const activeBadge = await screen.findByRole('link', { name: /ALL-03/ });
    expect(activeBadge).toHaveAttribute('href', '/run/123');
  });

  it('links to all runs for the current group', async () => {
    renderApp('/group/1');

    const link = await screen.findByRole('link', { name: /All runs for/ });
    expect(link).toHaveAttribute('href', '/group/1/runs');
  });

  it('does NOT show Generate Compliance Report button in user view', async () => {
    renderApp('/group/1');

    await screen.findByRole('heading', { name: 'Compliance for' });
    expect(
      screen.queryByRole('button', { name: 'Generate Compliance Report' })
    ).not.toBeInTheDocument();
  });

  it('shows Generate Compliance Report link in admin view', async () => {
    renderApp('/admin/group/1');

    const btn = await screen.findByRole('link', { name: 'Generate Compliance Report' });
    expect(btn).toHaveAttribute('href', '/admin/group/1/compliance_pdf');
  });

  it('admin view badges link to /admin/run/<id>', async () => {
    renderApp('/admin/group/1');

    // ALL-01 appears in multiple classes; check first occurrence
    const successBadges = await screen.findAllByRole('link', { name: /ALL-01/ });
    expect(successBadges[0]).toHaveAttribute('href', '/admin/run/120');
  });

  it('switches run group via dropdown', async () => {
    const user = userEvent.setup();
    renderApp('/group/1');

    await user.click(await screen.findByRole('button', { name: 'Battery Mk1' }));
    const other = await screen.findByRole('menuitem', { name: 'Battery Mk2' });
    expect(other).toHaveAttribute('href', '/group/2');
  });

  it('shows error alert when compliance fetch fails', async () => {
    server.use(
      http.get('/api/group/:runGroupId/compliance', () =>
        HttpResponse.json({ error: 'server error' }, { status: 502 })
      )
    );

    renderApp('/group/1');

    expect(
      await screen.findByText(/Unable to fetch compliance data\./)
    ).toBeInTheDocument();
  });

  it('shows empty state when no compliance classes exist', async () => {
    server.use(
      http.get('/api/group/:runGroupId/compliance', () =>
        HttpResponse.json({ compliance_by_class: [] })
      )
    );

    renderApp('/group/1');

    expect(
      await screen.findByText(/No compliance classes found/)
    ).toBeInTheDocument();
  });

  it('table row has a visible compliant indicator when class is met', async () => {
    server.use(
      http.get('/api/group/:runGroupId/compliance', () =>
        HttpResponse.json({
          compliance_by_class: [
            {
              class_name: 'A',
              class_details: { name: 'A', description: 'All DER clients.' },
              compliant: true,
              per_run_status: [
                {
                  test_procedure_id: 'ALL-01',
                  description: 'Discovery',
                  latest_run_id: 120,
                  status: 'success',
                },
              ],
            },
          ],
        })
      )
    );

    renderApp('/group/1');

    await screen.findByRole('cell', { name: 'A' });
    // The compliant row's first cell (th) carries the green background style
    const row = screen.getByRole('cell', { name: 'A' }).closest('tr')!;
    const indicator = row.querySelector('th')!;
    expect(indicator).toHaveStyle({ backgroundColor: 'var(--mantine-color-green-6)' });
  });
});
