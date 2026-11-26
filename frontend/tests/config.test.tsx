import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { describe, expect, it, vi } from 'vitest';
import configFixture from '../fixtures/config.json';
import * as configApi from '../src/api/config';
import { server } from './msw-server';
import { renderApp } from './test-utils';

// createCertificate / regenerateCertificate go through apiDownload (fetch -> blob -> synthetic <a>
// click), which is real browser download plumbing that jsdom can't faithfully emulate against
// MSW's fetch interception. That path is covered by Playwright; here we mock the API calls and
// assert on the resulting UI wiring (success/error notice) instead.
vi.mock('../src/api/config', async (importOriginal) => ({
  ...(await importOriginal<typeof configApi>()),
  createCertificate: vi.fn(),
  regenerateCertificate: vi.fn(),
}));

const NO_CERT_GROUP = {
  run_group_id: 3,
  name: 'No Cert Group',
  csip_aus_version: 'v1.2',
  created_at: '2026-06-01T00:00:00+00:00',
  is_static_uri: true,
  static_uri: 'https://example.com/dcap/static/3',
  assigned_certificate_id: null,
  certificate_name: null,
  is_device_cert: null,
  certificate_created_at: null,
  total_runs: 0,
};

const UNASSIGNED_CERT = {
  certificate_id: 21,
  name: 'Unused cert',
  is_device_cert: true,
  created_at: '2026-06-01T00:00:00+00:00',
  generated_at: '2026-06-01T00:00:00+00:00',
  expires_at: '2099-06-01T00:00:00+00:00',
  generation: 1,
  run_group_ids: [],
};

function mockConfig(overrides: Record<string, unknown>) {
  server.use(http.get('/api/config', () => HttpResponse.json({ ...configFixture, ...overrides })));
}

// [0] is the run groups table, [1] the certificates table (page order).
async function runGroupsTable() {
  return (await screen.findAllByRole('table'))[0];
}
async function certificatesTable() {
  return (await screen.findAllByRole('table'))[1];
}
async function runGroupRow(name: RegExp) {
  return within(await runGroupsTable()).getByRole('row', { name });
}

describe('config page', () => {
  it('shows heading and section titles', async () => {
    renderApp('/config');

    expect(
      await screen.findByRole('heading', { name: 'Certificates & Configuration' })
    ).toBeInTheDocument();
    expect(document.title).toBe('Certificates - CACTUS');
    expect(await screen.findByRole('heading', { name: 'IDENTITY' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'RUN GROUPS' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'CERTIFICATES' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'SUBSCRIPTION-BASED NOTIFICATIONS' })).toBeInTheDocument();
  });

  it('renders run groups from fixture', async () => {
    renderApp('/config');

    const table = await runGroupsTable();
    expect(within(table).getByText('Battery Mk1')).toBeInTheDocument();
    expect(within(table).getByText('Battery Mk2')).toBeInTheDocument();
    expect(within(table).getByText('Inverter X')).toBeInTheDocument();
    expect(within(table).getAllByText('v1.2')).toHaveLength(2);
    const runsLink = within(table).getByRole('link', { name: '6 runs' });
    expect(runsLink).toHaveAttribute('href', '/group/1/runs');
  });

  it('shows "New X Group" buttons for each CSIP-Aus version', async () => {
    renderApp('/config');

    expect(await screen.findByRole('button', { name: /New v1\.2 Group/ })).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: /New v1\.3-beta\/storage Group/ })
    ).toBeInTheDocument();
  });

  it("shows each run group's assigned certificate, including sharing", async () => {
    renderApp('/config');

    const mk1 = await runGroupRow(/Battery Mk1/);
    expect(within(mk1).getByText('Device cert · Battery Mk1 device')).toBeInTheDocument();
    expect(within(mk1).queryByText(/shared with/)).not.toBeInTheDocument();

    // Organisation aggregator is shared between Battery Mk2 and Inverter X
    for (const name of [/Battery Mk2/, /Inverter X/]) {
      const row = await runGroupRow(name);
      expect(
        within(row).getByText('Aggregator cert · Organisation aggregator')
      ).toBeInTheDocument();
      expect(within(row).getByText('shared with 1 other group')).toBeInTheDocument();
      expect(within(row).getByRole('button', { name: /Change/ })).toBeInTheDocument();
    }
  });

  it('only offers Generate Certificate for a run group when there are no certificates', async () => {
    mockConfig({ run_groups: [NO_CERT_GROUP], certificates: [] });

    renderApp('/config');

    const row = await runGroupRow(/No Cert Group/);
    expect(within(row).getByRole('button', { name: /Generate Certificate/ })).toBeInTheDocument();
    expect(within(row).queryByRole('button', { name: /Change/ })).not.toBeInTheDocument();
    expect(within(row).getByText('No certificate')).toBeInTheDocument();
    expect(screen.getByText(/No certificates yet/)).toBeInTheDocument();
  });

  it('shows getting-started checklist, all unchecked, for an empty config', async () => {
    mockConfig({ config: { subscription_domain: '', pen: null }, run_groups: [], certificates: [] });

    renderApp('/config');

    expect(await screen.findByText(/Getting started/)).toBeInTheDocument();
    expect(screen.getByText(/Set your organisation identity/)).toBeInTheDocument();
    expect(screen.getByText(/Set your notification domain/)).toBeInTheDocument();
    expect(screen.getByText(/Create a run group/)).toBeInTheDocument();
    expect(screen.getByText(/Generate a device or aggregator certificate/)).toBeInTheDocument();
    expect(screen.getByText(/Assign a certificate to your run group/)).toBeInTheDocument();
    expect(screen.getAllByRole('img', { name: 'To do' })).toHaveLength(5);
    expect(screen.queryByRole('img', { name: 'Done' })).not.toBeInTheDocument();
  });

  it.each([
    { label: 'run group only', certificates: [], todo: 4, done: 1 },
    { label: 'run group + unassigned certificate', certificates: [UNASSIGNED_CERT], todo: 3, done: 2 },
  ])('shows getting-started progress for $label', async ({ certificates, todo, done }) => {
    mockConfig({
      config: { subscription_domain: '', pen: null },
      run_groups: [NO_CERT_GROUP],
      certificates,
    });

    renderApp('/config');

    expect(await screen.findByText(/Getting started/)).toBeInTheDocument();
    expect(screen.getAllByRole('img', { name: 'To do' })).toHaveLength(todo);
    expect(screen.getAllByRole('img', { name: 'Done' })).toHaveLength(done);
  });

  it('hides the getting-started checklist once a run group has a certificate assigned', async () => {
    renderApp('/config');

    await screen.findByRole('heading', { name: 'RUN GROUPS' });
    expect(screen.queryByText(/Getting started/)).not.toBeInTheDocument();
  });

  it('shows Download Utility Server Certificates link', async () => {
    renderApp('/config');

    const link = await screen.findByRole('link', {
      name: /Download Utility Server Certificates/,
    });
    expect(link).toHaveAttribute('href', '/config/ca_cert');
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

    const table = await runGroupsTable();
    expect(
      within(table).getByText('https://reallyreallyreallylongtopleveldomainhere.com/dcap/static/1')
    ).toBeInTheDocument();
    expect(within(table).getAllByText('—')).toHaveLength(2); // Mk2 + Inverter X have no static URI
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

    await within(await runGroupsTable()).findByText('Battery Mk1');
    await user.click(screen.getAllByRole('button', { name: 'Rename' })[0]);

    const nameInput = await screen.findByDisplayValue('Battery Mk1');
    await user.clear(nameInput);
    await user.type(nameInput, 'Renamed Battery');
    await user.click(screen.getByRole('button', { name: 'Save' }));

    // Edit mode exits back to the read view showing the new name, with no flash of the old one.
    const table = await runGroupsTable();
    expect(await within(table).findByText('Renamed Battery')).toBeInTheDocument();
    expect(screen.queryByDisplayValue('Renamed Battery')).not.toBeInTheDocument();
    expect(screen.queryByText('Battery Mk1')).not.toBeInTheDocument();
    // The certificates table reflects the new name too
    expect(within(await certificatesTable()).getByText('Renamed Battery')).toBeInTheDocument();
  });

  it('disables Save while the rename draft is empty or unchanged', async () => {
    const user = userEvent.setup();
    renderApp('/config');

    await within(await runGroupsTable()).findByText('Battery Mk1');
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

    await within(await runGroupsTable()).findByText('Battery Mk1');
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

    await within(await runGroupsTable()).findByText('Battery Mk1');
    await user.click(screen.getAllByRole('button', { name: 'Rename' })[0]);

    const nameInput = await screen.findByDisplayValue('Battery Mk1');
    await user.type(nameInput, ' Renamed');
    await user.keyboard('{Escape}');

    expect(screen.queryByDisplayValue('Battery Mk1 Renamed')).not.toBeInTheDocument();
    expect(await within(await runGroupsTable()).findByText('Battery Mk1')).toBeInTheDocument();
    expect(patched).toBe(false);
  });

  // ---- Certificates section ----

  it('lists certificates with the run groups using them', async () => {
    renderApp('/config');

    const table = await certificatesTable();
    const mk1 = within(table).getByRole('row', { name: /Battery Mk1 device/ });
    expect(within(mk1).getByText('Device')).toBeInTheDocument();
    expect(within(mk1).getByText('Battery Mk1')).toBeInTheDocument();
    expect(within(mk1).getByRole('link', { name: 'Download Battery Mk1 device' })).toHaveAttribute(
      'href',
      '/config/certificates/11'
    );

    const org = within(table).getByRole('row', { name: /Organisation aggregator/ });
    expect(within(org).getByText('Aggregator')).toBeInTheDocument();
    expect(within(org).getByText('Battery Mk2')).toBeInTheDocument();
    expect(within(org).getByText('Inverter X')).toBeInTheDocument();

    const spare = within(table).getByRole('row', { name: /Spare device/ });
    expect(within(spare).getByText('Not assigned')).toBeInTheDocument();
  });

  it('flags expired certificates', async () => {
    mockConfig({
      certificates: configFixture.certificates.map((c) =>
        c.certificate_id === 11 ? { ...c, expires_at: '2020-01-01T00:00:00+00:00' } : c
      ),
    });

    renderApp('/config');

    const table = await certificatesTable();
    expect(within(table).getByText(/^Expired /)).toBeInTheDocument();
    const mk1 = await runGroupRow(/Battery Mk1/);
    expect(within(mk1).getByText(/· expired/)).toBeInTheDocument();
  });

  it('generates a new certificate and assigns it to the chosen run groups', async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.createCertificate).mockResolvedValueOnce({ unassignedRunGroupIds: [] });
    renderApp('/config');

    await user.click(await screen.findByRole('button', { name: /New Certificate/ }));
    const dialog = await screen.findByRole('dialog');
    const submit = within(dialog).getByRole('button', { name: /Generate & Download/ });
    expect(submit).toBeDisabled(); // no name yet

    await user.type(within(dialog).getByRole('textbox'), 'Org cert 2');
    await user.click(within(dialog).getByRole('radio', { name: /Aggregator/ }));
    await user.click(within(dialog).getByRole('checkbox', { name: /Battery Mk2/ }));
    await user.click(within(dialog).getByRole('checkbox', { name: /Inverter X/ }));
    await user.click(submit);

    expect(configApi.createCertificate).toHaveBeenCalledWith('Org cert 2', 'aggregator', [2, 3]);
    expect(
      await screen.findByText(/Certificate "Org cert 2" generated — your download should begin/)
    ).toBeInTheDocument();
  });

  it("pre-selects the run group when generating from a run group's row", async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.createCertificate).mockResolvedValueOnce({ unassignedRunGroupIds: [] });
    renderApp('/config');

    await user.click(within(await runGroupRow(/Battery Mk1/)).getByRole('button', { name: /New/ }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByRole('checkbox', { name: /Battery Mk1/ })).toBeChecked();
    expect(within(dialog).getByRole('checkbox', { name: /Battery Mk2/ })).not.toBeChecked();

    await user.type(within(dialog).getByRole('textbox'), 'Mk1 v2');
    await user.click(within(dialog).getByRole('button', { name: /Generate & Download/ }));

    expect(configApi.createCertificate).toHaveBeenCalledWith('Mk1 v2', 'device', [1]);
  });

  it('disables the aggregator certificate option when no domain is set', async () => {
    const user = userEvent.setup();
    mockConfig({ config: { subscription_domain: '', pen: null } });
    renderApp('/config');

    await user.click(await screen.findByRole('button', { name: /New Certificate/ }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByRole('radio', { name: /Aggregator/ })).toBeDisabled();
    expect(within(dialog).getByRole('radio', { name: /Device/ })).toBeEnabled();
  });

  it('warns when a new certificate could not be assigned to some run groups', async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.createCertificate).mockResolvedValueOnce({ unassignedRunGroupIds: [3] });
    renderApp('/config');

    await user.click(await screen.findByRole('button', { name: /New Certificate/ }));
    const dialog = await screen.findByRole('dialog');
    await user.type(within(dialog).getByRole('textbox'), 'x');
    await user.click(within(dialog).getByRole('checkbox', { name: /Inverter X/ }));
    await user.click(within(dialog).getByRole('button', { name: /Generate & Download/ }));

    expect(
      await screen.findByText(/generated but could not be assigned to: Inverter X/)
    ).toBeInTheDocument();
  });

  it('shows error when certificate generation fails', async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.createCertificate).mockRejectedValueOnce(
      new Error('Failed to generate certificate.')
    );
    renderApp('/config');

    await user.click(await screen.findByRole('button', { name: /New Certificate/ }));
    const dialog = await screen.findByRole('dialog');
    await user.type(within(dialog).getByRole('textbox'), 'x');
    await user.click(within(dialog).getByRole('button', { name: /Generate & Download/ }));

    expect(await screen.findByText(/Failed to generate certificate/)).toBeInTheDocument();
  });

  it("changes a run group's certificate", async () => {
    const user = userEvent.setup();
    let assigned: unknown = null;
    server.use(
      http.put('/api/run_groups/:runGroupId/certificate', async ({ params, request }) => {
        assigned = { runGroupId: Number(params.runGroupId), body: await request.json() };
        return HttpResponse.json(configFixture.run_groups[0]);
      })
    );
    renderApp('/config');

    await user.click(within(await runGroupRow(/Battery Mk1/)).getByRole('button', { name: /Change/ }));
    const dialog = await screen.findByRole('dialog');
    const save = within(dialog).getByRole('button', { name: 'Save' });
    expect(save).toBeDisabled(); // unchanged
    expect(within(dialog).getByRole('radio', { name: /Battery Mk1 device/ })).toBeChecked();
    // Sharing is surfaced when choosing
    expect(within(dialog).getByText('Also used by: Battery Mk2, Inverter X')).toBeInTheDocument();

    await user.click(within(dialog).getByRole('radio', { name: /Spare device/ }));
    await user.click(save);

    await waitFor(() => expect(assigned).toEqual({ runGroupId: 1, body: { certificate_id: 13 } }));
    expect(
      await screen.findByText(/Battery Mk1 now uses certificate "Spare device"/)
    ).toBeInTheDocument();
  });

  it("removes a run group's certificate", async () => {
    const user = userEvent.setup();
    let unassignedId: number | null = null;
    server.use(
      http.delete('/api/run_groups/:runGroupId/certificate', ({ params }) => {
        unassignedId = Number(params.runGroupId);
        return HttpResponse.json({ ...configFixture.run_groups[1], assigned_certificate_id: null });
      })
    );
    renderApp('/config');

    await user.click(within(await runGroupRow(/Battery Mk2/)).getByRole('button', { name: /Change/ }));
    const dialog = await screen.findByRole('dialog');
    await user.click(within(dialog).getByRole('radio', { name: /No certificate/ }));
    await user.click(within(dialog).getByRole('button', { name: 'Save' }));

    await waitFor(() => expect(unassignedId).toBe(2));
    expect(await screen.findByText(/Battery Mk2 no longer has a certificate/)).toBeInTheDocument();
  });

  it('regenerates a certificate after confirming which run groups are affected', async () => {
    const user = userEvent.setup();
    vi.mocked(configApi.regenerateCertificate).mockResolvedValueOnce(undefined);
    renderApp('/config');

    await user.click(
      within(await certificatesTable()).getByRole('button', {
        name: 'Regenerate Organisation aggregator',
      })
    );
    const dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByText(/Battery Mk2, Inverter X/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Regenerate & Download' }));

    expect(configApi.regenerateCertificate).toHaveBeenCalledWith(12);
    expect(
      await screen.findByText(/Certificate "Organisation aggregator" regenerated/)
    ).toBeInTheDocument();
  });

  it('deletes a certificate after confirmation', async () => {
    const user = userEvent.setup();
    let deletedId: number | null = null;
    server.use(
      http.delete('/api/certificates/:certificateId', ({ params }) => {
        deletedId = Number(params.certificateId);
        return HttpResponse.json({});
      })
    );
    renderApp('/config');

    await user.click(
      within(await certificatesTable()).getByRole('button', { name: 'Delete Battery Mk1 device' })
    );
    const dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByText(/Battery Mk1 will be left without a certificate/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Delete' }));

    await waitFor(() => expect(deletedId).toBe(11));
    expect(await screen.findByText(/Certificate "Battery Mk1 device" deleted/)).toBeInTheDocument();
  });

  it('shows the orchestrator error when a certificate can not be deleted', async () => {
    const user = userEvent.setup();
    server.use(
      http.delete('/api/certificates/:certificateId', () =>
        HttpResponse.json(
          { error: 'Cannot delete certificate 13 while in use by active run(s) 5.' },
          { status: 502 }
        )
      )
    );
    renderApp('/config');

    await user.click(
      within(await certificatesTable()).getByRole('button', { name: 'Delete Spare device' })
    );
    await user.click(
      within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Delete' })
    );

    expect(await screen.findByText(/while in use by active run\(s\) 5/)).toBeInTheDocument();
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
