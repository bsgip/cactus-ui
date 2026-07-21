import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';
import sessionAdminFixture from '../fixtures/session_admin.json';
import sessionUnauthenticatedFixture from '../fixtures/session_unauthenticated.json';
import { server } from './msw-server';
import { renderApp } from './test-utils';

describe('home page (logged in)', () => {
  it('renders the welcome content and navbar for the session fixture', async () => {
    renderApp();

    expect(await screen.findByRole('heading', { name: 'Welcome to CACTUS' })).toBeInTheDocument();
    expect(screen.getByText('User: Test User')).toBeInTheDocument();

    for (const link of ['Procedures', 'Runs', 'Playlists', 'Compliance', 'Config']) {
      expect(screen.getByRole('link', { name: link })).toBeInTheDocument();
    }
    expect(screen.getByRole('link', { name: 'Logout' })).toHaveAttribute('href', '/logout');

    // Regular users must not see the admin dropdown
    expect(screen.queryByRole('button', { name: 'Admin' })).not.toBeInTheDocument();

    expect(screen.getByRole('heading', { name: 'Help & Resources' })).toBeInTheDocument();

    // Footer version link
    expect(screen.getByRole('link', { name: 'v1.6.3' })).toHaveAttribute(
      'href',
      'https://github.com/bsgip/cactus-deploy/releases/tag/v1.6.3'
    );
  });

  it('shows the admin links inside the Admin dropdown for an admin session', async () => {
    const user = userEvent.setup();
    server.use(http.get('/api/session', () => HttpResponse.json(sessionAdminFixture)));
    renderApp();

    await user.click(await screen.findByRole('button', { name: 'Admin' }));

    expect(await screen.findByRole('menuitem', { name: 'Manage Users' })).toHaveAttribute(
      'href',
      '/admin'
    );
    expect(screen.getByRole('menuitem', { name: 'Compliance' })).toHaveAttribute(
      'href',
      '/admin/compliance'
    );
    expect(screen.getByRole('menuitem', { name: 'Platform Stats' })).toHaveAttribute(
      'href',
      '/admin/stats'
    );
  });

  it('shows the dismissible banner message when set', async () => {
    server.use(
      http.get('/api/session', () =>
        HttpResponse.json({
          username: 'Test User',
          permissions: ['user:all'],
          version: 'v1.6.3',
          support_email: 'support@bsgip.com',
          banner_message: 'Scheduled maintenance tonight',
          hosted_images: [],
        })
      )
    );
    renderApp();

    expect(await screen.findByText('Scheduled maintenance tonight')).toBeInTheDocument();
  });
});

describe('login screen (logged out)', () => {
  it('renders the login screen when /api/session returns 401', async () => {
    server.use(
      http.get('/api/session', () =>
        HttpResponse.json(sessionUnauthenticatedFixture, { status: 401 })
      )
    );
    renderApp();

    expect(
      await screen.findByRole('heading', { name: '🌵 Welcome to CACTUS' })
    ).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Login' })).toHaveAttribute('href', '/login');
    expect(
      screen.getByText(/CSIP-Australia Compliance Testing for Utility Services/)
    ).toBeInTheDocument();
  });

  it('shows the login banner message when present in the 401 body', async () => {
    server.use(
      http.get('/api/session', () =>
        HttpResponse.json(
          { error: 'unauthenticated', login_banner_message: 'Logins are disabled for maintenance' },
          { status: 401 }
        )
      )
    );
    renderApp();

    expect(await screen.findByText('Logins are disabled for maintenance')).toBeInTheDocument();
  });
});

describe('error state', () => {
  it('shows the shared error alert when /api/session fails', async () => {
    server.use(http.get('/api/session', () => HttpResponse.json({}, { status: 502 })));
    renderApp();

    expect(
      await screen.findByText(
        'Unable to communicate with test server. Please try refreshing the page or re-logging in.'
      )
    ).toBeInTheDocument();
  });
});
