import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';
import { server } from './msw-server';
import { renderApp } from './test-utils';

describe('config page', () => {
  it('shows heading and section titles', async () => {
    renderApp('/config');

    expect(
      await screen.findByRole('heading', { name: 'Certificates & Configuration' })
    ).toBeInTheDocument();
    expect(document.title).toBe('Certificates - CACTUS');
    expect(screen.getByRole('heading', { name: 'Organisation Identity' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Run Groups' })).toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: 'Utility Server Certificates' })
    ).toBeInTheDocument();
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
          config: { subscription_domain: '', pen: null },
          run_groups: [
            {
              run_group_id: 3,
              name: 'No Cert Group',
              csip_aus_version: 'v1.2',
              created_at: '2026-06-01T00:00:00+00:00',
              is_static_uri: true,
              static_uri: 'https://example.com/dcap/static/3',
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

  it('shows getting-started callout when list is empty', async () => {
    server.use(
      http.get('/api/config', () =>
        HttpResponse.json({
          config: { subscription_domain: '', pen: null },
          run_groups: [],
          csip_aus_versions: [{ version: 'v1.2' }],
        })
      )
    );

    renderApp('/config');

    expect(await screen.findByText(/Getting started/)).toBeInTheDocument();
  });

  it('shows Download Utility Server Certificates link', async () => {
    renderApp('/config');

    const link = await screen.findByRole('link', {
      name: /Download Utility Server Certificates/,
    });
    expect(link).toHaveAttribute('href', '/config/ca_cert');
  });

  it('enables the shared aggregator cert button when a domain is set', async () => {
    renderApp('/config');

    // Default fixture has a subscription domain, so the shared-cert action is enabled.
    expect(
      await screen.findByRole('button', { name: /Aggregator cert for all groups/ })
    ).toBeEnabled();
  });

  it('disables the shared aggregator cert button when no domain is set', async () => {
    server.use(
      http.get('/api/config', () =>
        HttpResponse.json({
          config: { subscription_domain: '', pen: null },
          run_groups: [
            {
              run_group_id: 1,
              name: 'Only Group',
              csip_aus_version: 'v1.2',
              created_at: '2026-05-01T00:00:00+00:00',
              is_static_uri: true,
              static_uri: 'https://example.com/dcap/static/1',
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

    expect(
      await screen.findByRole('button', { name: /Aggregator cert for all groups/ })
    ).toBeDisabled();
  });

  it('disables the per-group aggregator cert option when no domain is set', async () => {
    const user = userEvent.setup();
    server.use(
      http.get('/api/config', () =>
        HttpResponse.json({
          config: { subscription_domain: '', pen: null },
          run_groups: [
            {
              run_group_id: 1,
              name: 'Only Group',
              csip_aus_version: 'v1.2',
              created_at: '2026-05-01T00:00:00+00:00',
              is_static_uri: true,
              static_uri: 'https://example.com/dcap/static/1',
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

    await user.click(await screen.findByRole('button', { name: /Device Certificate/ }));
    expect(
      await screen.findByRole('button', { name: /Aggregator Certificate/ })
    ).toBeDisabled();
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

  it('shows each run group DeviceCapability URI from fixture', async () => {
    renderApp('/config');

    expect(await screen.findByText('https://example.com/dcap/static/1')).toBeInTheDocument();
    expect(screen.getByText('https://example.com/dcap/static/2')).toBeInTheDocument();
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

    const penInput = await screen.findByPlaceholderText(/123456/);
    await user.clear(penInput);
    await user.type(penInput, '999999');
    await user.click(screen.getByRole('button', { name: /Save PEN/ }));

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

    const domainInput = await screen.findByPlaceholderText(/my\.example\.com/);
    await user.clear(domainInput);
    await user.type(domainInput, 'new.example.com');
    await user.click(screen.getByRole('button', { name: /Save Domain/ }));

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
