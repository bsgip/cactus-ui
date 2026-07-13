import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { describe, expect, it, vi } from 'vitest';
import configFixture from '../fixtures/config.json';
import * as configApi from '../src/api/config';
import { server } from './msw-server';
import { renderApp } from './test-utils';

// generateRunGroupCert goes through apiDownload (fetch -> blob -> synthetic <a> click), which is
// real browser download plumbing that jsdom can't faithfully emulate against MSW's fetch
// interception. That path is covered by Playwright; here we mock the API call and assert on the
// resulting UI wiring (success/error notice) instead.
vi.mock('../src/api/config', async (importOriginal) => ({
  ...(await importOriginal<typeof configApi>()),
  generateRunGroupCert: vi.fn(),
}));

describe('config page', () => {
  it('shows heading and section titles', async () => {
    renderApp('/config');

    expect(
      await screen.findByRole('heading', { name: 'Certificates & Configuration' })
    ).toBeInTheDocument();
    expect(document.title).toBe('Certificates - CACTUS');
    expect(await screen.findByRole('heading', { name: 'Organisation Setup' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Run Groups' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Subscription Notifications' })).toBeInTheDocument();
  });

  it('renders run groups from fixture', async () => {
    renderApp('/config');

    expect(await screen.findByText('Battery Mk1')).toBeInTheDocument();
    expect(screen.getByText('Battery Mk2')).toBeInTheDocument();
    expect(screen.getByText('v1.2')).toBeInTheDocument();
    const runsLink = screen.getByRole('link', { name: '6 runs' });
    expect(runsLink).toHaveAttribute('href', '/group/1/runs');
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

    // Battery Mk1 and Mk2 both have certificates in the fixture. The issued date renders in the
    // local timezone, so compute the expectation the same way the component does.
    const issued = new Date('2026-05-01T00:05:00+00:00').toLocaleDateString('sv');
    expect(await screen.findAllByRole('button', { name: /Manage Certificate/ })).toHaveLength(2);
    expect(screen.getByText(`Device cert · issued ${issued}`)).toBeInTheDocument();
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
    expect(screen.getByText('No certificate')).toBeInTheDocument();
  });

  it('shows getting-started checklist, all unchecked, for an empty config', async () => {
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
    expect(screen.getByText(/Set your organisation identity/)).toBeInTheDocument();
    expect(screen.getByText(/Create a run group/)).toBeInTheDocument();
    expect(screen.getByText(/Generate a device or aggregator certificate/)).toBeInTheDocument();
    expect(screen.getAllByRole('img', { name: 'To do' })).toHaveLength(3);
    expect(screen.queryByRole('img', { name: 'Done' })).not.toBeInTheDocument();
  });

  it('shows getting-started checklist with the run-group step checked once one exists', async () => {
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

    expect(await screen.findByText(/Getting started/)).toBeInTheDocument();
    // Identity and certificate steps are still to do; only the run-group step is done.
    expect(screen.getAllByRole('img', { name: 'To do' })).toHaveLength(2);
    expect(screen.getAllByRole('img', { name: 'Done' })).toHaveLength(1);
  });

  it('hides the getting-started checklist once a run group and certificate both exist', async () => {
    renderApp('/config');

    await screen.findByRole('heading', { name: 'Run Groups' });
    expect(screen.queryByText(/Getting started/)).not.toBeInTheDocument();
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

    await user.click(await screen.findByRole('button', { name: /Manage Certificate/ }));
    expect(await screen.findByRole('button', { name: /Aggregator Certificate/ })).toBeDisabled();
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

    // Confirm button stays disabled until the run group name is typed in full.
    const confirmBtn = await screen.findByRole('button', { name: /Delete Battery Mk1/ });
    expect(confirmBtn).toBeDisabled();
    await user.type(within(screen.getByRole('dialog')).getByRole('textbox'), 'Battery Mk1');
    expect(confirmBtn).toBeEnabled();
    await user.click(confirmBtn);

    await waitFor(() => expect(deleted).toBe(true));
  });

  it('resets the delete acknowledgement when the dialog is dismissed without confirming', async () => {
    const user = userEvent.setup();
    renderApp('/config');

    // Type the confirmation, then dismiss the dialog via Escape instead of Cancel.
    await user.click((await screen.findAllByRole('button', { name: /Delete/ }))[0]);
    await user.type(within(await screen.findByRole('dialog')).getByRole('textbox'), 'Battery Mk1');
    expect(screen.getByRole('button', { name: /Delete Battery Mk1/ })).toBeEnabled();
    await user.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());

    // Reopening must not leave the destructive button pre-armed.
    await user.click(screen.getAllByRole('button', { name: /Delete/ })[0]);
    expect(within(await screen.findByRole('dialog')).getByRole('textbox')).toHaveValue('');
    expect(screen.getByRole('button', { name: /Delete Battery Mk1/ })).toBeDisabled();
  });

  it('disables Save PEN / Save Domain until the value is edited', async () => {
    const user = userEvent.setup();
    renderApp('/config');

    const savePen = await screen.findByRole('button', { name: /Save PEN/ });
    const saveDomain = screen.getByRole('button', { name: /Save Domain/ });
    expect(savePen).toBeDisabled();
    expect(saveDomain).toBeDisabled();

    await user.type(screen.getByPlaceholderText(/123456/), '9');
    expect(savePen).toBeEnabled();
    expect(saveDomain).toBeDisabled();
  });

  it('asks for confirmation before updating an already-set PEN, then saves', async () => {
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

    // Fixture PEN is populated, so a confirmation dialog appears first.
    expect(penSent).toBeUndefined();
    await user.click(await screen.findByRole('button', { name: 'Update' }));

    await waitFor(() => expect(penSent).toBe(999999));
    expect(await screen.findByText('Saved')).toBeInTheDocument();
  });

  it('asks for confirmation before updating an already-set domain, then saves', async () => {
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

    expect(
      await screen.findByText(/manually regenerate your existing aggregator certificates/)
    ).toBeInTheDocument();
    expect(domainSent).toBeUndefined();
    await user.click(screen.getByRole('button', { name: 'Update' }));

    await waitFor(() => expect(domainSent).toBe('new.example.com'));
    expect(await screen.findByText('Saved')).toBeInTheDocument();
  });

  it('does not send the update when the confirmation is cancelled', async () => {
    const user = userEvent.setup();
    let domainSent = false;

    server.use(
      http.post('/api/config/domain', () => {
        domainSent = true;
        return HttpResponse.json({});
      })
    );

    renderApp('/config');

    const domainInput = await screen.findByPlaceholderText(/my\.example\.com/);
    await user.clear(domainInput);
    await user.type(domainInput, 'new.example.com');
    await user.click(screen.getByRole('button', { name: /Save Domain/ }));

    await user.click(await screen.findByRole('button', { name: 'Cancel' }));
    expect(domainSent).toBe(false);
  });

  it('saves immediately without confirmation when the domain was not previously set', async () => {
    const user = userEvent.setup();
    let domainSent: string | undefined;

    server.use(
      http.get('/api/config', () =>
        HttpResponse.json({
          config: { subscription_domain: '', pen: null },
          run_groups: [],
          csip_aus_versions: [{ version: 'v1.2' }],
        })
      ),
      http.post('/api/config/domain', async ({ request }) => {
        const body = (await request.json()) as { subscription_domain: string };
        domainSent = body.subscription_domain;
        return HttpResponse.json({});
      })
    );

    renderApp('/config');

    const domainInput = await screen.findByPlaceholderText(/my\.example\.com/);
    await user.type(domainInput, 'first.example.com');
    await user.click(screen.getByRole('button', { name: /Save Domain/ }));

    await waitFor(() => expect(domainSent).toBe('first.example.com'));
    expect(await screen.findByText('Saved')).toBeInTheDocument();
  });

  it('saves on Enter key press when the field is dirty', async () => {
    const user = userEvent.setup();
    let domainSent: string | undefined;

    server.use(
      http.get('/api/config', () =>
        HttpResponse.json({
          config: { subscription_domain: '', pen: null },
          run_groups: [],
          csip_aus_versions: [{ version: 'v1.2' }],
        })
      ),
      http.post('/api/config/domain', async ({ request }) => {
        const body = (await request.json()) as { subscription_domain: string };
        domainSent = body.subscription_domain;
        return HttpResponse.json({});
      })
    );

    renderApp('/config');

    const domainInput = await screen.findByPlaceholderText(/my\.example\.com/);
    await user.type(domainInput, 'first.example.com{Enter}');

    await waitFor(() => expect(domainSent).toBe('first.example.com'));
    expect(await screen.findByText('Saved')).toBeInTheDocument();
  });

  it('pressing Enter with no edits does not submit', async () => {
    const user = userEvent.setup();
    let domainSent = false;

    server.use(
      http.post('/api/config/domain', () => {
        domainSent = true;
        return HttpResponse.json({});
      })
    );

    renderApp('/config');

    const domainInput = await screen.findByPlaceholderText(/my\.example\.com/);
    domainInput.focus();
    await user.keyboard('{Enter}');

    expect(domainSent).toBe(false);
  });

  it('renames a run group via click-to-edit (pencil -> type -> Save)', async () => {
    const user = userEvent.setup();
    let currentName = 'Battery Mk1';

    // GET reflects the PATCH so the test can prove the read view never shows the stale name:
    // the row stays in edit mode (Save pending) until the refetched config lands.
    server.use(
      http.get('/api/config', () =>
        HttpResponse.json({
          ...configFixture,
          run_groups: [
            { ...configFixture.run_groups[0], name: currentName },
            configFixture.run_groups[1],
          ],
        })
      ),
      http.patch('/api/run_groups/:id', async ({ request }) => {
        const body = (await request.json()) as { name: string };
        currentName = body.name;
        return HttpResponse.json({});
      })
    );

    renderApp('/config');

    await screen.findByText('Battery Mk1');
    await user.click(screen.getAllByRole('button', { name: 'Rename' })[0]);

    const nameInput = await screen.findByDisplayValue('Battery Mk1');
    await user.clear(nameInput);
    await user.type(nameInput, 'Renamed Battery');
    await user.click(screen.getByRole('button', { name: 'Save' }));

    // Edit mode exits back to the read view showing the new name, with no flash of the old one.
    expect(await screen.findByText('Renamed Battery')).toBeInTheDocument();
    expect(screen.queryByDisplayValue('Renamed Battery')).not.toBeInTheDocument();
    expect(screen.queryByText('Battery Mk1')).not.toBeInTheDocument();
  });

  it('disables Save while the rename draft is empty or unchanged', async () => {
    const user = userEvent.setup();
    renderApp('/config');

    await screen.findByText('Battery Mk1');
    await user.click(screen.getAllByRole('button', { name: 'Rename' })[0]);

    const nameInput = await screen.findByDisplayValue('Battery Mk1');
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();

    await user.clear(nameInput);
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();

    await user.type(nameInput, 'Battery Mk1b');
    expect(screen.getByRole('button', { name: 'Save' })).toBeEnabled();
  });

  it('saves a run group name on Enter key press', async () => {
    const user = userEvent.setup();
    let nameSent: string | undefined;

    server.use(
      http.patch('/api/run_groups/:id', async ({ request }) => {
        const body = (await request.json()) as { name: string };
        nameSent = body.name;
        return HttpResponse.json({});
      })
    );

    renderApp('/config');

    await screen.findByText('Battery Mk1');
    await user.click(screen.getAllByRole('button', { name: 'Rename' })[0]);

    const nameInput = await screen.findByDisplayValue('Battery Mk1');
    await user.clear(nameInput);
    await user.type(nameInput, 'Renamed Battery{Enter}');

    await waitFor(() => expect(nameSent).toBe('Renamed Battery'));
  });

  it('cancels a run group rename on Escape without saving', async () => {
    const user = userEvent.setup();
    let patched = false;

    server.use(
      http.patch('/api/run_groups/:id', () => {
        patched = true;
        return HttpResponse.json({});
      })
    );

    renderApp('/config');

    await screen.findByText('Battery Mk1');
    await user.click(screen.getAllByRole('button', { name: 'Rename' })[0]);

    const nameInput = await screen.findByDisplayValue('Battery Mk1');
    await user.type(nameInput, ' Renamed');
    await user.keyboard('{Escape}');

    expect(screen.queryByDisplayValue('Battery Mk1 Renamed')).not.toBeInTheDocument();
    expect(await screen.findByText('Battery Mk1')).toBeInTheDocument();
    expect(patched).toBe(false);
  });

  it('shows a success notice after generating a device certificate', async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.generateRunGroupCert).mockResolvedValueOnce(undefined);
    renderApp('/config');

    await user.click((await screen.findAllByRole('button', { name: /Manage Certificate/ }))[0]);
    await user.click(
      await screen.findByRole('button', { name: 'Replace with Device Certificate' })
    );

    expect(configApi.generateRunGroupCert).toHaveBeenCalledWith(1, 'device');
    expect(
      await screen.findByText(/Certificate generated — your download should begin automatically/)
    ).toBeInTheDocument();
  });

  it('shows a success notice after generating a shared aggregator certificate', async () => {
    const user = userEvent.setup();
    renderApp('/config');

    await user.click(await screen.findByRole('button', { name: /Aggregator cert for all groups/ }));
    await user.click(await screen.findByRole('button', { name: /Generate & apply to all groups/ }));

    expect(
      await screen.findByText(
        /Aggregator certificate generated and applied to all run groups — download starting/
      )
    ).toBeInTheDocument();
  });

  it('shows error when certificate generation fails', async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.generateRunGroupCert).mockRejectedValueOnce(
      new Error('Failed to generate certificate.')
    );

    renderApp('/config');

    await user.click((await screen.findAllByRole('button', { name: /Manage Certificate/ }))[0]);
    await user.click(
      await screen.findByRole('button', { name: 'Replace with Device Certificate' })
    );

    expect(await screen.findByText(/Failed to generate certificate/)).toBeInTheDocument();
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
    await user.type(within(screen.getByRole('dialog')).getByRole('textbox'), 'Battery Mk1');
    await user.click(confirmBtn);

    expect(await screen.findByText(/Failed to delete run group/)).toBeInTheDocument();
  });
});
