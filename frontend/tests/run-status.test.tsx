import { MantineProvider } from '@mantine/core';
import { ModalsProvider } from '@mantine/modals';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { createMemoryRouter, RouterProvider } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import shellFinalised from '../fixtures/run_status_shell_finalised.json';
import shellLive from '../fixtures/run_status_shell.json';
import shellPlaylist from '../fixtures/run_status_shell_playlist.json';
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
    ],
    { initialEntries: [path] }
  );
  return render(
    <MantineProvider>
      <QueryClientProvider client={queryClient}>
        <ModalsProvider>
          <RouterProvider router={router} />
        </ModalsProvider>
      </QueryClientProvider>
    </MantineProvider>
  );
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
    useShell({ ...shellLive, run_status: 'initialised' });
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
    useShell({ ...shellFinalised, is_immediate_start: true });
    renderRunStatus('/run/120');
    await screen.findByRole('heading', { name: 'Run 120 [Finalised]' });
    expect(screen.queryByRole('button', { name: 'Active Power Chart' })).not.toBeInTheDocument();
  });

  it('points the user at support when a finalised run has no artifacts', async () => {
    useShell({ ...shellFinalised, run_has_artifacts: false });
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
      ...shellFinalised,
      run_id: 999,
      run_is_live: false,
      run_status: null,
      run_has_artifacts: null,
    });
    renderRunStatus('/run/999');
    expect(await screen.findByRole('heading', { name: 'Run 999 Not Found' })).toBeInTheDocument();
    expect(screen.getByText(/does not exist/)).toBeInTheDocument();
  });

  it('renders a skipped message for a skipped run', async () => {
    useShell({ ...shellFinalised, run_status: 'skipped', run_has_artifacts: false });
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
    expect(within(banner).getByRole('link', { name: /ALL-01/ })).toHaveAttribute('href', '/run/201');
    expect(within(banner).getByRole('link', { name: 'Download artifacts' })).toHaveAttribute(
      'href',
      '/run/201/artifact'
    );
  });

  it('confirms before ending the playlist and then finalises it', async () => {
    useShell(shellPlaylist);
    const assign = vi.fn();
    Object.defineProperty(window, 'location', {
      value: { ...window.location, assign },
      writable: true,
    });
    const finalised = vi.fn();
    server.use(
      http.post('/api/runs/:runId/finalise_playlist', ({ params }) => {
        finalised(Number(params.runId));
        return HttpResponse.json({ run_id: Number(params.runId) });
      })
    );

    const user = userEvent.setup();
    renderRunStatus('/run/202');

    await user.click(await screen.findByRole('button', { name: /End Playlist/ }));
    // Confirmation modal — confirm via the button inside the dialog.
    const dialog = await screen.findByRole('dialog');
    await user.click(within(dialog).getByRole('button', { name: 'End Playlist' }));

    await waitFor(() => expect(finalised).toHaveBeenCalledWith(202));
    await waitFor(() => expect(assign).toHaveBeenCalledWith('/playlists'));
  });

  it('warns and links to the active test when viewing a not-yet-active run', async () => {
    useShell({
      ...shellPlaylist,
      run_id: 203,
      run_status: 'initialised',
      playlist_info: { ...shellPlaylist.playlist_info, current_order: 2 },
    });
    renderRunStatus('/run/203');

    expect(await screen.findByText('This Test is Not Yet Active')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Go to Active Test/ })).toHaveAttribute(
      'href',
      '/run/202'
    );
  });
});

beforeEach(() => {
  vi.stubGlobal('scrollTo', vi.fn());
});

afterEach(() => {
  vi.unstubAllGlobals();
});
