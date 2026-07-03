import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';
import { server } from './msw-server';
import { renderApp } from './test-utils';

describe('admin page', () => {
  it('shows heading and Platform Stats link', async () => {
    renderApp('/admin');

    expect(await screen.findByRole('heading', { name: 'Admin' })).toBeInTheDocument();
    expect(document.title).toBe('Admin - CACTUS');

    const statsLink = screen.getByRole('link', { name: 'Platform Stats' });
    expect(statsLink).toHaveAttribute('href', '/admin/stats');
  });

  it('renders users from fixture', async () => {
    renderApp('/admin');

    // User 1: named
    expect(await screen.findByText('1')).toBeInTheDocument();
    expect(screen.getByText('Alice Example')).toBeInTheDocument();

    // Run group links for user 1
    const mk1Link = screen.getByRole('link', { name: 'Battery Mk1 (10)' });
    expect(mk1Link).toHaveAttribute('href', '/admin/group/10/runs');
    const mk2Link = screen.getByRole('link', { name: 'Battery Mk2 (11)' });
    expect(mk2Link).toHaveAttribute('href', '/admin/group/11/runs');

    // User 2: no name
    expect(screen.getByText('-')).toBeInTheDocument();
    // User 2 has no run groups
    expect(screen.getByText('No run groups found.')).toBeInTheDocument();
  });

  it('filters users by search text', async () => {
    const user = userEvent.setup();
    renderApp('/admin');

    await screen.findByText('Alice Example');

    const input = screen.getByPlaceholderText(
      'Search by user name, run group name or by user/run groups IDs'
    );
    await user.type(input, 'Alice');

    // User 1 still visible
    expect(screen.getByText('Alice Example')).toBeInTheDocument();
    // User 2 (matchable_description is "2") filtered out — no "No run groups found." visible
    expect(screen.queryByText('No run groups found.')).not.toBeInTheDocument();
  });

  it('shows "No users found." when filter matches nothing', async () => {
    const user = userEvent.setup();
    renderApp('/admin');

    await screen.findByText('Alice Example');

    const input = screen.getByPlaceholderText(
      'Search by user name, run group name or by user/run groups IDs'
    );
    await user.type(input, 'xyzthisdoesnotmatch');

    expect(await screen.findByText('No users found.')).toBeInTheDocument();
  });

  it('shows error alert when fetch fails', async () => {
    server.use(
      http.get('/api/admin/users', () =>
        HttpResponse.json({ error: 'server error' }, { status: 502 })
      )
    );

    renderApp('/admin');

    expect(await screen.findByText('Unable to fetch users.')).toBeInTheDocument();
  });

  it('shows access denied on 403', async () => {
    server.use(
      http.get('/api/admin/users', () => HttpResponse.json({ error: 'forbidden' }, { status: 403 }))
    );

    renderApp('/admin');

    expect(await screen.findByText('Access denied.')).toBeInTheDocument();
  });
});
