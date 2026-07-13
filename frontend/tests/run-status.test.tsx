import { Theme } from '@radix-ui/themes';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { createMemoryRouter, RouterProvider } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import shellFinalised from '../fixtures/run_status_shell_finalised.json';
import shellLive from '../fixtures/run_status_shell.json';
import shellPlaylist from '../fixtures/run_status_shell_playlist.json';
import runnerInitialised from '../fixtures/run_status_runner_initialised.json';
import { RunStatusPage } from '../src/pages/RunStatus/RunStatusPage';
import { server } from './msw-server';

// The run status page is still "dark" (not wired into the router until 9d), so render it
// directly behind a minimal router that supplies the :runId param for both views.
function renderRunStatus(path: string) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const router = createMemoryRouter(
    [
      { path: '/run/:runId', element: <RunStatusPage isAdminView={false} /> },
      { path: '/admin/run/:runId', element: <RunStatusPage isAdminView /> },
      // Destination for End Playlist navigation; content is irrelevant to the assertions.
      { path: '/playlists', element: <div /> },
    ],
    { initialEntries: [path] }
  );
  return {
    router,
    ...render(
      <Theme accentColor="blue" grayColor="slate" radius="medium">
        <QueryClientProvider client={queryClient}>
          <RouterProvider router={router} />
        </QueryClientProvider>
      </Theme>
    ),
  };
}

// Make the shell endpoints return a specific payload for this test.
function useShell(payload: Record<string, unknown>) {
  server.use(
    http.get('/api/run/:runId', () => HttpResponse.json(payload)),
    http.get('/api/admin/run/:runId', () => HttpResponse.json(payload))
  );
}

describe('run status page chrome', () => {
  it('renders the live header card with a finalise control for a started standalone run', async () => {
    renderRunStatus('/run/123');

    expect(await screen.findByRole('heading', { name: 'Run 123 (started)' })).toBeInTheDocument();
    expect(screen.getByText('https://cactus.example/run/123')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Finalise' })).toBeEnabled();
    expect(screen.queryByText(/Playlist:/)).not.toBeInTheDocument();
  });

  it('disables the finalise control in the admin view', async () => {
    renderRunStatus('/admin/run/123');
    expect(await screen.findByRole('button', { name: 'Finalise' })).toBeDisabled();
  });

  it('shows a Start control while initialised', async () => {
    useShell({ ...shellLive, run: { ...shellLive.run, status: 'initialised' } });
    renderRunStatus('/run/123');
    expect(await screen.findByRole('button', { name: 'Start' })).toBeEnabled();
  });

  it('offers an artifact download and the active power chart for a finalised run', async () => {
    useShell(shellFinalised);
    const user = userEvent.setup();
    renderRunStatus('/run/120');

    expect(await screen.findByRole('heading', { name: 'Run 120 [Finalised]' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Download Artifacts' })).toHaveAttribute(
      'href',
      '/run/120/artifact'
    );

    // The chart form is revealed on demand and posts the video offset to the report route.
    await user.click(screen.getByRole('button', { name: 'Active Power Chart' }));
    const createChart = await screen.findByRole('button', { name: 'Create Chart' });
    expect(createChart.closest('form')).toHaveAttribute('action', '/run/120/html_report');
    expect(screen.getByLabelText('Video timestamp')).toBeInTheDocument();
  });

  it('hides the active power chart for immediate-start procedures', async () => {
    useShell({ ...shellFinalised, run: { ...shellFinalised.run, immediate_start: true } });
    renderRunStatus('/run/120');
    await screen.findByRole('heading', { name: 'Run 120 [Finalised]' });
    expect(screen.queryByRole('button', { name: 'Active Power Chart' })).not.toBeInTheDocument();
  });

  it('points the user at support when a finalised run has no artifacts', async () => {
    useShell({ ...shellFinalised, run: { ...shellFinalised.run, has_artifacts: false } });
    renderRunStatus('/run/120');

    await screen.findByRole('heading', { name: 'Run 120 [Finalised]' });
    expect(screen.getByText(/no artifacts/i)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'support@bsgip.com' })).toHaveAttribute(
      'href',
      'mailto:support@bsgip.com'
    );
    expect(screen.queryByRole('link', { name: 'Download Artifacts' })).not.toBeInTheDocument();
  });

  it('renders a not-found message for a missing run', async () => {
    useShell({
      run: null,
      run_is_live: false,
      playlist_name: null,
      playlist_runs: null,
    });
    renderRunStatus('/run/999');
    expect(await screen.findByRole('heading', { name: 'Run 999 Not Found' })).toBeInTheDocument();
    expect(screen.getByText(/does not exist/)).toBeInTheDocument();
  });

  it('renders a skipped message for a skipped run', async () => {
    useShell({
      ...shellFinalised,
      run: { ...shellFinalised.run, status: 'skipped', has_artifacts: false },
    });
    renderRunStatus('/run/120');
    expect(await screen.findByRole('heading', { name: 'Run 120 [Skipped]' })).toBeInTheDocument();
    expect(screen.getByText(/never executed/)).toBeInTheDocument();
  });
});

describe('run status playlist banner', () => {
  it('renders the playlist badges and current-test summary', async () => {
    useShell(shellPlaylist);
    renderRunStatus('/run/202');

    expect(await screen.findByText('Playlist: Smoke Test Playlist')).toBeInTheDocument();
    expect(screen.getByText(/Viewing: Test 2 of 3/)).toBeInTheDocument();

    // The finalised first run links to its run page and offers an artifact download.
    const banner = screen
      .getByText('Playlist: Smoke Test Playlist')
      .closest('[role="alert"]') as HTMLElement;
    expect(within(banner).getByRole('link', { name: /ALL-01/ })).toHaveAttribute(
      'href',
      '/run/201'
    );
    expect(within(banner).getByRole('link', { name: 'Download artifacts' })).toHaveAttribute(
      'href',
      '/run/201/artifact'
    );
  });

  it('confirms before ending the playlist and then finalises it', async () => {
    useShell(shellPlaylist);
    const finalised = vi.fn();
    server.use(
      http.post('/api/runs/:runId/finalise_playlist', ({ params }) => {
        finalised(Number(params.runId));
        return HttpResponse.json({ run_id: Number(params.runId) });
      })
    );

    const user = userEvent.setup();
    const { router } = renderRunStatus('/run/202');

    await user.click(await screen.findByRole('button', { name: /End Playlist/ }));
    // Confirmation modal (Radix AlertDialog) — confirm via the button inside it.
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'End Playlist' }));

    await waitFor(() => expect(finalised).toHaveBeenCalledWith(202));
    await waitFor(() => expect(router.state.location.pathname).toBe('/playlists'));
  });

  it('warns and links to the active test when viewing a not-yet-active run', async () => {
    useShell({
      ...shellPlaylist,
      run: {
        ...shellPlaylist.run,
        run_id: 203,
        test_procedure_id: 'ALL-03',
        status: 'initialised',
        playlist_order: 2,
      },
    });
    renderRunStatus('/run/203');

    expect(await screen.findByText('This Test is Not Yet Active')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Go to Active Test/ })).toHaveAttribute(
      'href',
      '/run/202'
    );
  });
});

describe('run status live panels', () => {
  it('renders the general, criteria, steps, requests and log panels', async () => {
    renderRunStatus('/run/123');

    // Procedure heading links to the procedure YAML page.
    expect(await screen.findByRole('link', { name: 'ALL-08' })).toHaveAttribute(
      'href',
      '/procedure/ALL-08'
    );
    expect(screen.getByText('Test in progress - 1 of 3 steps complete')).toBeInTheDocument();
    // Preconditions only matter during the init phase; this run has started so they're hidden.
    expect(screen.queryByText('Precondition Checks')).not.toBeInTheDocument();
    // Synthetic all-xsd-valid criterion (1 of 3 requests failed validation).
    expect(screen.getByText('all-xsd-valid')).toBeInTheDocument();
    expect(screen.getByText('1 of 3 request(s) have XSD validation errors')).toBeInTheDocument();
    // Steps (POST-DERSTATUS only appears in the steps table) + the Envoy log text.
    expect(screen.getByText('POST-DERSTATUS')).toBeInTheDocument();
    expect(screen.getByText(/GET \/edev -> 200/)).toBeInTheDocument();
    // Timeline card renders (the chart canvas itself is verified in Playwright).
    expect(screen.getByText('Timeline')).toBeInTheDocument();
  });

  it('shows precondition checks while the run has not yet started', async () => {
    server.use(http.get('/api/run/:runId/status', () => HttpResponse.json(runnerInitialised)));
    renderRunStatus('/run/123');

    expect(await screen.findByText('Precondition Checks')).toBeInTheDocument();
    expect(screen.getByText('edevice-registered')).toBeInTheDocument();
  });

  it('opens the request details modal from the requests table', async () => {
    const user = userEvent.setup();
    renderRunStatus('/run/123');

    const detailButtons = await screen.findAllByRole('button', { name: 'Details' });
    await user.click(detailButtons[0]);

    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText(/DERCapability/)).toBeInTheDocument();
    expect(within(dialog).getByText(/400 Bad Request/)).toBeInTheDocument();
  });

  it('shows the latest XSD validation error', async () => {
    renderRunStatus('/run/123');
    expect(await screen.findByText('Latest XSD Validation Error')).toBeInTheDocument();
    expect(screen.getByText(/Element 'rtgMaxW': This element is not expected/)).toBeInTheDocument();
  });

  it('opens the DER device details modal', async () => {
    const user = userEvent.setup();
    renderRunStatus('/run/123');

    await user.click(await screen.findByRole('button', { name: 'Device Details' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('DER Capability')).toBeInTheDocument();
    expect(within(dialog).getByText('COMBINED_PV_AND_STORAGE')).toBeInTheDocument();
  });

  it('sends a proceed signal for a step blocked on proceed', async () => {
    const proceeded = vi.fn();
    server.use(
      http.post('/api/runs/:runId/proceed', ({ params }) => {
        proceeded(Number(params.runId));
        return HttpResponse.json({ handled: true });
      })
    );
    const user = userEvent.setup();
    renderRunStatus('/run/123');

    await user.click(await screen.findByRole('button', { name: /Proceed to next step/ }));
    await waitFor(() => expect(proceeded).toHaveBeenCalledWith(123));
  });

  it('shows the active step in the bottom status banner', async () => {
    renderRunStatus('/run/123');
    expect(await screen.findByText('Step 2: POST-DERSETTINGS')).toBeInTheDocument();
  });

  it('enriches the initialised header card with pre-start instructions', async () => {
    useShell({ ...shellLive, run: { ...shellLive.run, status: 'initialised' } });
    renderRunStatus('/run/123');

    expect(
      await screen.findByText('Please ensure the following before starting the test:')
    ).toBeInTheDocument();
    expect(
      screen.getByText('Confirm the inverter is exporting before proceeding')
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Start' })).toBeEnabled();
  });
});

beforeEach(() => {
  vi.stubGlobal('scrollTo', vi.fn());
});

afterEach(() => {
  vi.unstubAllGlobals();
});
