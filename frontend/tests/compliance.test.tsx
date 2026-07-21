import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';
import type { ComplianceRequestResponse, RunResponse } from '../src/api/types';
import { server } from './msw-server';
import { renderApp } from './test-utils';

function makeRequest(
  overrides: Partial<ComplianceRequestResponse> = {}
): ComplianceRequestResponse {
  return {
    compliance_request_id: 1,
    created_at: '2024-06-01T00:00:00Z',
    created_by: 1,
    updated_at: '2024-06-01T00:00:00Z',
    updated_by: 1,
    status: 1,
    classes: ['DECEW'],
    runs: [5],
    csip_aus_version: 'v1.3',
    witnessed_at: '2024-06-15T00:00:00Z',
    der_brand: 'Acme',
    der_oem: 'OEM',
    der_series: 'S1',
    der_representative_models: 'M1',
    software_client_type: 'direct',
    software_client_providers: 'P',
    software_client_versions: '1.0',
    onsite_hardware_details: 'gw',
    ...overrides,
  };
}

function makeRun(run_id: number, test_procedure_id: string): RunResponse {
  return {
    all_criteria_met: true,
    classes: ['DECEW'],
    created_at: '2024-06-01T00:00:00Z',
    finalised_at: '2024-06-01T00:00:00Z',
    has_artifacts: true,
    immediate_start: false,
    is_device_cert: true,
    playlist_execution_id: null,
    playlist_order: null,
    playlist_runs: null,
    run_id,
    status: 'finalised',
    test_procedure_id,
    test_url: '',
  };
}

const FORM_DATA = {
  csipaus_versions: ['v1.3'],
  compliance_classes: [{ name: 'DECEW', description: 'Energise / de-energise' }],
  tests_by_version_and_class: { 'v1.3': { DECEW: ['ALL-01'] } },
  completed_test_procedures: ['ALL-01'],
  successful_runs: [makeRun(5, 'ALL-01')],
};

describe('compliance list page', () => {
  it('renders the user requests with status and edit/delete actions', async () => {
    server.use(
      http.get('/api/compliance/requests', () =>
        HttpResponse.json({ requests: [makeRequest({ compliance_request_id: 42, status: 1 })] })
      )
    );

    renderApp('/compliance');

    expect(await screen.findByRole('heading', { name: 'Compliance' })).toBeInTheDocument();
    expect(await screen.findByText('42')).toBeInTheDocument();
    // Submitted (user wording) + a class badge
    expect(screen.getByText('Submitted')).toBeInTheDocument();
    expect(screen.getByText('DECEW')).toBeInTheDocument();
    // Submitted user request → edit + delete actions
    expect(screen.getByTitle('Review / edit compliance request')).toBeInTheDocument();
    expect(screen.getByTitle('Delete compliance request (permanent)')).toBeInTheDocument();
  });

  it('shows the admin view with client info and a download link for finalised requests', async () => {
    server.use(
      http.get('/api/admin/compliance/requests', () =>
        HttpResponse.json({
          requests: [
            {
              ...makeRequest({ compliance_request_id: 9, status: 4 }),
              created_by_user: { user_id: 7, subject_id: 's', issuer_id: 'i', user_name: 'Alice' },
              updated_by_user: { user_id: 7, subject_id: 's', issuer_id: 'i', user_name: 'Alice' },
            },
          ],
        })
      )
    );

    renderApp('/admin/compliance');

    expect(await screen.findByText('Alice')).toBeInTheDocument();
    expect(screen.getByText('Finalised')).toBeInTheDocument();
    const download = screen.getByTitle('Download compliance report').closest('a');
    expect(download).toHaveAttribute('href', '/admin/compliance/requests/9/artifact');
  });

  it('filters the admin list by request id', async () => {
    const user = userEvent.setup();
    server.use(
      http.get('/api/admin/compliance/requests', () =>
        HttpResponse.json({
          requests: [
            {
              ...makeRequest({ compliance_request_id: 11 }),
              created_by_user: { user_id: 1, subject_id: 's', issuer_id: 'i', user_name: 'A' },
              updated_by_user: { user_id: 1, subject_id: 's', issuer_id: 'i', user_name: 'A' },
            },
            {
              ...makeRequest({ compliance_request_id: 22 }),
              created_by_user: { user_id: 2, subject_id: 's', issuer_id: 'i', user_name: 'B' },
              updated_by_user: { user_id: 2, subject_id: 's', issuer_id: 'i', user_name: 'B' },
            },
          ],
        })
      )
    );

    renderApp('/admin/compliance');

    expect(await screen.findByText('11')).toBeInTheDocument();
    await user.type(screen.getByPlaceholderText('Search by compliance request ID'), '22');

    expect(screen.queryByText('11')).not.toBeInTheDocument();
    expect(screen.getByText('22')).toBeInTheDocument();
  });
});

describe('compliance request wizard', () => {
  it('steps through the wizard and submits a new request with preselected class and run', async () => {
    const user = userEvent.setup();
    let posted: unknown = null;
    server.use(
      http.get('/api/compliance/form-data', () => HttpResponse.json(FORM_DATA)),
      http.post('/api/compliance/requests', async ({ request }) => {
        posted = await request.json();
        return HttpResponse.json(makeRequest(), { status: 201 });
      })
    );

    const { router } = renderApp('/compliance-request');

    expect(await screen.findByRole('heading', { name: 'Compliance Request' })).toBeInTheDocument();

    // Witness date (the only required field not auto-filled).
    const dateInput = document.querySelector('input[type="date"]') as HTMLInputElement;
    fireEvent.change(dateInput, { target: { value: '2024-06-15' } });

    // Walk to the last step via Next.
    await user.click(screen.getByRole('button', { name: 'Next' })); // -> Classes & Runs
    await user.click(screen.getByRole('button', { name: 'Next' })); // -> DER
    await user.click(screen.getByRole('button', { name: 'Next' })); // -> Software Client

    const submit = screen.getByRole('button', { name: 'Submit' });
    expect(submit).toBeEnabled();
    await user.click(submit);

    await waitFor(() => expect(posted).not.toBeNull());
    expect(posted).toMatchObject({
      csip_aus_version: 'v1.3',
      witnessed_at: '2024-06-15',
      classes: ['DECEW'],
      runs: [5],
    });
    await waitFor(() => expect(router.state.location.pathname).toBe('/compliance'));
  });

  it('disables inputs in view mode and closes back to the list', async () => {
    const user = userEvent.setup();
    server.use(
      http.get('/api/compliance/form-data', () => HttpResponse.json(FORM_DATA)),
      // Direct navigation (no router state): the wizard fetches the request to prefill.
      http.get('/api/compliance/requests/1', () => HttpResponse.json(makeRequest()))
    );

    const { router } = renderApp(
      '/compliance-request?prefill=1&prefill-classes=true&prefill-runs=true&action=view'
    );

    // DER step has plain text inputs we can assert are disabled.
    await screen.findByRole('heading', { name: 'Compliance Request' });
    await user.click(screen.getByRole('button', { name: 'Next' }));
    await user.click(screen.getByRole('button', { name: 'Next' }));

    const der = await screen.findByRole('heading', { name: 'DER' });
    const brand = within(der.parentElement as HTMLElement).getAllByRole('textbox')[0];
    expect(brand).toBeDisabled();

    // View mode closes immediately (no discard confirmation).
    await user.click(screen.getByRole('button', { name: 'Close' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/compliance'));
  });
});
