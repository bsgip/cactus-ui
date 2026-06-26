import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';
import { server } from './msw-server';
import { renderApp } from './test-utils';

describe('playlists page', () => {
  it('shows the run group header, test library, and an empty queue', async () => {
    renderApp('/group/1/playlists');

    expect(await screen.findByRole('button', { name: 'Battery Mk1' })).toBeInTheDocument();
    expect(document.title).toBe('Playlists - CACTUS');

    // Categories (native <details>/<summary> accordion) and tests from the fixture
    expect(await screen.findByText('Registration')).toBeInTheDocument();
    expect(screen.getAllByText('ALL-01').length).toBeGreaterThan(0);

    // Empty queue + disabled Start
    expect(screen.getByText(/Pick tests from the/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Start Playlist' })).toBeDisabled();
  });

  it('switches run groups through the dropdown', async () => {
    const user = userEvent.setup();
    const { router } = renderApp('/group/1/playlists');

    await user.click(await screen.findByRole('button', { name: 'Battery Mk1' }));
    await user.click(await screen.findByRole('menuitem', { name: 'Battery Mk2' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/group/2/playlists'));
  });

  it('adds a test to the queue and enables Start Playlist', async () => {
    const user = userEvent.setup();
    renderApp('/group/1/playlists');

    const libraryRow = await screen.findByRole('button', { name: /ALL-01/ });
    await user.click(libraryRow);

    // Queue now lists the test and Start is enabled
    expect(await screen.findByRole('button', { name: /Remove ALL-01/ })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Start Playlist' })).toBeEnabled();
  });

  it('navigates to the run status page when a playlist starts', async () => {
    const user = userEvent.setup();
    const { router } = renderApp('/group/1/playlists');

    await user.click(await screen.findByRole('button', { name: /ALL-01/ }));
    await user.click(screen.getByRole('button', { name: 'Start Playlist' }));

    await waitFor(() => expect(router.state.location.pathname).toBe('/run/301'));
  });

  it('shows the active playlist with go-to-run and finalise controls', async () => {
    renderApp('/group/1/playlists');

    expect(await screen.findByText('Active Playlist')).toBeInTheDocument();
    const sessionLink = await screen.findByRole('link', { name: 'active-e' });
    expect(sessionLink).toHaveAttribute('href', '/run/201');

    // Go to run targets the first started/initialised run (202 is started)
    const goToRun = screen.getByRole('link', { name: /Go to run/ });
    expect(goToRun).toHaveAttribute('href', '/run/202');
    expect(screen.getByRole('button', { name: /Finalise Playlist/ })).toBeInTheDocument();
  });

  it('shows past sessions with a download-all link', async () => {
    const user = userEvent.setup();
    renderApp('/group/1/playlists');

    const pastLink = await screen.findByRole('link', { name: 'past-exe' });
    expect(pastLink).toHaveAttribute('href', '/run/150');

    // Open the download menu for the past session (two runs have artifacts -> Download All)
    const downloadButtons = screen.getAllByRole('button', { name: 'Download artifacts' });
    await user.click(downloadButtons[0]);
    const downloadAll = await screen.findByRole('menuitem', { name: /Download All/ });
    expect(downloadAll).toHaveAttribute('href', '/playlist/artifacts?run_ids=150,151');
  });

  it('shows an error when the test library fails to load', async () => {
    server.use(
      http.get('/api/group/:runGroupId/playlist_tests', () =>
        HttpResponse.json({ error: 'Unable to fetch test procedures.' }, { status: 502 })
      )
    );
    renderApp('/group/1/playlists');

    expect(
      await screen.findByText('Unable to fetch test procedures.')
    ).toBeInTheDocument();
  });
});
