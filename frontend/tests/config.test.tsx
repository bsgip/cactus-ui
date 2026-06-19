import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';
import { server } from './msw-server';
import { renderApp } from './test-utils';

describe('config page', () => {
  it('shows heading and section titles', async () => {
    renderApp('/config');

    expect(await screen.findByRole('heading', { name: 'User Configuration' })).toBeInTheDocument();
    expect(document.title).toBe('Certificate - CACTUS');
    expect(await screen.findByRole('heading', { name: 'Run Groups' })).toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: 'Private Enterprise Number (PEN)' })
    ).toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: 'Subscription Notification Domain (Optional)' })
    ).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'DeviceCapability URI' })).toBeInTheDocument();
  });

  it('renders run groups from fixture', async () => {
    renderApp('/config');

    expect(await screen.findByDisplayValue('Battery Mk1')).toBeInTheDocument();
    expect(screen.getByDisplayValue('Battery Mk2')).toBeInTheDocument();
    expect(screen.getByText('v1.2')).toBeInTheDocument();
    expect(screen.getByText('6 total run(s)')).toBeInTheDocument();
  });

  it('shows "New X Group" buttons for each CSIP-Aus version', async () => {
    renderApp('/config');

    expect(await screen.findByRole('button', { name: /New v1\.2 Group/ })).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: /New v1\.3-beta\/storage Group/ })
    ).toBeInTheDocument();
  });

  it('shows certificate button for run group with cert', async () => {
    renderApp('/config');

    // Battery Mk1 has is_device_cert=true and a cert
    expect(await screen.findByRole('button', { name: /Device Certificate/ })).toBeInTheDocument();
  });

  it('shows Generate Certificate button for run group without cert', async () => {
    server.use(
      http.get('/api/config', () =>
        HttpResponse.json({
          config: { subscription_domain: '', is_static_uri: false, pen: null, static_uri: null },
          run_groups: [
            {
              run_group_id: 3,
              name: 'No Cert Group',
              csip_aus_version: 'v1.2',
              created_at: '2026-06-01T00:00:00+00:00',
              is_device_cert: null,
              certificate_id: null,
              certificate_created_at: null,
              total_runs: 0,
            },
          ],
          csip_aus_versions: [{ version: 'v1.2' }],
        })
      )
    );

    renderApp('/config');

    expect(await screen.findByRole('button', { name: /Generate Certificate/ })).toBeInTheDocument();
  });

  it('shows no run groups alert when list is empty', async () => {
    server.use(
      http.get('/api/config', () =>
        HttpResponse.json({
          config: { subscription_domain: '', is_static_uri: false, pen: null, static_uri: null },
          run_groups: [],
          csip_aus_versions: [{ version: 'v1.2' }],
        })
      )
    );

    renderApp('/config');

    expect(await screen.findByText(/There are no Run Groups configured/)).toBeInTheDocument();
  });

  it('shows Download SERCA Certificate link', async () => {
    renderApp('/config');

    const link = await screen.findByRole('link', { name: /Download SERCA Certificate/ });
    expect(link).toHaveAttribute('href', '/config/ca_cert');
  });

  it('shows Advanced Options only when > 1 run groups', async () => {
    renderApp('/config');

    expect(await screen.findByRole('button', { name: 'Advanced Options' })).toBeInTheDocument();
  });

  it('does NOT show Advanced Options with 1 run group', async () => {
    server.use(
      http.get('/api/config', () =>
        HttpResponse.json({
          config: { subscription_domain: '', is_static_uri: false, pen: null, static_uri: null },
          run_groups: [
            {
              run_group_id: 1,
              name: 'Only Group',
              csip_aus_version: 'v1.2',
              created_at: '2026-05-01T00:00:00+00:00',
              is_device_cert: true,
              certificate_id: 11,
              certificate_created_at: '2026-05-01T00:05:00+00:00',
              total_runs: 1,
            },
          ],
          csip_aus_versions: [{ version: 'v1.2' }],
        })
      )
    );

    renderApp('/config');

    await screen.findByRole('heading', { name: 'Run Groups' });
    expect(screen.queryByRole('button', { name: 'Advanced Options' })).not.toBeInTheDocument();
  });

  it('renders PEN from fixture', async () => {
    renderApp('/config');

    // PEN input should be pre-filled with 123456
    expect(await screen.findByDisplayValue('123456')).toBeInTheDocument();
  });

  it('renders domain from fixture', async () => {
    renderApp('/config');

    expect(await screen.findByDisplayValue('my.example.com')).toBeInTheDocument();
  });

  it('shows per run group static/dynamic URI badges from fixture', async () => {
    renderApp('/config');

    // Battery Mk1 is static (with a static_uri), Battery Mk2 is dynamic
    expect(await screen.findByText('Static URI')).toBeInTheDocument();
    expect(screen.getByText('Dynamic URI')).toBeInTheDocument();
    expect(screen.getByText('https://example.com/dcap/static/1')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Swap to dynamic/ })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Swap to static/ })).toBeInTheDocument();
  });

  it('calls the run group static URI API when swapping', async () => {
    const user = userEvent.setup();
    let sent: { is_static_uri?: boolean } | undefined;

    server.use(
      http.patch('/api/run_groups/:id', async ({ request }) => {
        sent = (await request.json()) as { is_static_uri: boolean };
        return HttpResponse.json({});
      })
    );

    renderApp('/config');

    // Battery Mk2 is dynamic in the fixture, so it offers "Swap to static"
    const swapBtn = await screen.findByRole('button', { name: /Swap to static/ });
    await user.click(swapBtn);

    await waitFor(() => expect(sent?.is_static_uri).toBe(true));
  });

  it('shows error alert when config fetch fails', async () => {
    server.use(
      http.get('/api/config', () => HttpResponse.json({ error: 'server error' }, { status: 502 }))
    );

    renderApp('/config');

    expect(await screen.findByText(/Unable to communicate with test server/)).toBeInTheDocument();
  });

  it('calls delete run group API and invalidates config', async () => {
    const user = userEvent.setup();
    let deleted = false;

    server.use(
      http.delete('/api/run_groups/:id', () => {
        deleted = true;
        return HttpResponse.json({});
      })
    );

    renderApp('/config');

    // Open the first Delete modal (Battery Mk1)
    const deleteButtons = await screen.findAllByRole('button', { name: /Delete/ });
    await user.click(deleteButtons[0]);

    // Confirm in the modal
    const confirmBtn = await screen.findByRole('button', { name: /Delete Battery Mk1/ });
    await user.click(confirmBtn);

    await waitFor(() => expect(deleted).toBe(true));
  });

  it('calls update PEN API', async () => {
    const user = userEvent.setup();
    let penSent: number | undefined;

    server.use(
      http.post('/api/config/pen', async ({ request }) => {
        const body = (await request.json()) as { pen: number };
        penSent = body.pen;
        return HttpResponse.json({});
      })
    );

    renderApp('/config');

    const penInput = await screen.findByPlaceholderText(/Enter PEN/);
    await user.clear(penInput);
    await user.type(penInput, '999999');
    await user.click(screen.getByRole('button', { name: /Update PEN/ }));

    await waitFor(() => expect(penSent).toBe(999999));
  });

  it('calls update domain API', async () => {
    const user = userEvent.setup();
    let domainSent: string | undefined;

    server.use(
      http.post('/api/config/domain', async ({ request }) => {
        const body = (await request.json()) as { subscription_domain: string };
        domainSent = body.subscription_domain;
        return HttpResponse.json({});
      })
    );

    renderApp('/config');

    const domainInput = await screen.findByPlaceholderText(/Enter a FQDN/);
    await user.clear(domainInput);
    await user.type(domainInput, 'new.example.com');
    await user.click(screen.getByRole('button', { name: /Update Domain/ }));

    await waitFor(() => expect(domainSent).toBe('new.example.com'));
  });

  it('shows error when delete fails', async () => {
    const user = userEvent.setup();

    server.use(
      http.delete('/api/run_groups/:id', () =>
        HttpResponse.json({ error: 'Failed to delete run group' }, { status: 502 })
      )
    );

    renderApp('/config');

    const deleteButtons = await screen.findAllByRole('button', { name: /Delete/ });
    await user.click(deleteButtons[0]);

    const confirmBtn = await screen.findByRole('button', { name: /Delete Battery Mk1/ });
    await user.click(confirmBtn);

    expect(await screen.findByText(/Failed to delete run group/)).toBeInTheDocument();
  });
});
