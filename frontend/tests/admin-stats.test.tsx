import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';
import { server } from './msw-server';
import { renderApp } from './test-utils';

describe('admin stats page', () => {
  it('shows heading and back link', async () => {
    renderApp('/admin/stats');

    expect(await screen.findByRole('heading', { name: 'Platform Stats' })).toBeInTheDocument();
    expect(document.title).toBe('Platform Stats - CACTUS');

    const backLink = screen.getByRole('link', { name: /back to admin/i });
    expect(backLink).toHaveAttribute('href', '/admin');
  });

  it('renders summary cards from fixture', async () => {
    renderApp('/admin/stats');

    // max_run_number = 52 (Total Runs card) — unique in the fixture
    expect(await screen.findByText('52')).toBeInTheDocument();
    // avg runs per user = 47/12 = 3.9 — unique
    expect(screen.getByText('3.9')).toBeInTheDocument();
    // deleted label: 52 - 47 = 5 deleted
    expect(screen.getByText(/incl\. 5 deleted/)).toBeInTheDocument();
    // card labels (multiple matches ok — just confirm they're present)
    expect(screen.getAllByText('Total Runs').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Total Users').length).toBeGreaterThan(0);
    expect(screen.getByText('Avg Runs per User')).toBeInTheDocument();
  });

  it('renders CSIP-AUS versions', async () => {
    renderApp('/admin/stats');

    await screen.findByRole('heading', { name: 'Platform Stats' });

    expect(screen.getByText('1.0')).toBeInTheDocument();
    expect(screen.getByText('2.0')).toBeInTheDocument();
    expect(screen.getByText('2 run groups')).toBeInTheDocument();
    expect(screen.getByText('6 run groups')).toBeInTheDocument();
  });

  it('renders compliance totals and pass rate', async () => {
    renderApp('/admin/stats');

    // total_passed=31 total_failed=9 → assessed=40 → 77.5%
    expect(await screen.findByText('31')).toBeInTheDocument();
    expect(screen.getByText('9')).toBeInTheDocument();
    expect(screen.getByText('77.5%')).toBeInTheDocument();
  });

  it('renders procedure table with fixture rows', async () => {
    renderApp('/admin/stats');

    await screen.findByRole('heading', { name: 'Platform Stats' });

    expect(screen.getByText('S-ALL-01')).toBeInTheDocument();
    expect(screen.getByText('S-ALL-02')).toBeInTheDocument();
    expect(screen.getByText('C-BESS-01')).toBeInTheDocument();
    // fixture has 5 procedures (<20), so no "Show all" button
    expect(screen.queryByRole('button', { name: /show all.*procedures/i })).not.toBeInTheDocument();
  });

  it('shows "Show all N procedures" button when >20 procedures', async () => {
    const user = userEvent.setup();
    const manyProcedures = Array.from({ length: 25 }, (_, i) => ({
      test_procedure_id: `P-${String(i + 1).padStart(2, '0')}`,
      classes: [],
      total_runs: 25 - i,
      passed: 1,
      failed: 0,
      latest_passed: 1,
      latest_failed: 0,
    }));
    server.use(
      http.get('/api/admin/stats', () =>
        HttpResponse.json({
          total_users: 1,
          total_run_groups: 1,
          total_runs: 5,
          total_passed: 3,
          total_failed: 2,
          max_run_number: 5,
          version_counts: {},
          user_leaderboard: [],
          procedures: manyProcedures,
          runs_per_week: [],
        })
      )
    );

    renderApp('/admin/stats');

    await screen.findByRole('heading', { name: 'Platform Stats' });

    // Should only show first 20
    expect(screen.getByText('P-01')).toBeInTheDocument();
    expect(screen.queryByText('P-25')).not.toBeInTheDocument();

    const showAllBtn = screen.getByRole('button', { name: /show all 25 procedures/i });
    await user.click(showAllBtn);

    expect(screen.getByText('P-25')).toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: /show all 25 procedures/i })
    ).not.toBeInTheDocument();
  });

  it('renders user leaderboard from fixture', async () => {
    renderApp('/admin/stats');

    await screen.findByRole('heading', { name: 'Platform Stats' });

    expect(screen.getByText('Alice Example')).toBeInTheDocument();
    expect(screen.getByText('Bob Test')).toBeInTheDocument();
    expect(screen.getByText('20')).toBeInTheDocument();
  });

  it('shows "Show all N users" button when >20 users', async () => {
    const user = userEvent.setup();
    const manyUsers = Array.from({ length: 25 }, (_, i) => ({
      name: `User ${i + 1}`,
      run_count: 25 - i,
    }));
    server.use(
      http.get('/api/admin/stats', () =>
        HttpResponse.json({
          total_users: 25,
          total_run_groups: 1,
          total_runs: 100,
          total_passed: 50,
          total_failed: 10,
          max_run_number: 105,
          version_counts: {},
          user_leaderboard: manyUsers,
          procedures: [],
          runs_per_week: [],
        })
      )
    );

    renderApp('/admin/stats');

    await screen.findByRole('heading', { name: 'Platform Stats' });

    expect(screen.getByText('User 1')).toBeInTheDocument();
    expect(screen.queryByText('User 25')).not.toBeInTheDocument();

    const showAllBtn = screen.getByRole('button', { name: /show all 25 users/i });
    await user.click(showAllBtn);

    expect(screen.getByText('User 25')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /show all 25 users/i })).not.toBeInTheDocument();
  });

  it('shows error alert when fetch fails', async () => {
    server.use(
      http.get('/api/admin/stats', () =>
        HttpResponse.json({ error: 'server error' }, { status: 502 })
      )
    );

    renderApp('/admin/stats');

    expect(await screen.findByText('Failed to retrieve stats.')).toBeInTheDocument();
  });

  it('shows access denied on 403', async () => {
    server.use(
      http.get('/api/admin/stats', () => HttpResponse.json({ error: 'forbidden' }, { status: 403 }))
    );

    renderApp('/admin/stats');

    expect(await screen.findByText('Access denied.')).toBeInTheDocument();
  });
});
