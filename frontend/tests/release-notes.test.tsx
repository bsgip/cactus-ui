import { screen, within } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';
import type { ReleaseNotesResponse } from '../src/api/types';
import { server } from './msw-server';
import { renderApp } from './test-utils';

function makeResponse(overrides: Partial<ReleaseNotesResponse> = {}): ReleaseNotesResponse {
  return {
    releases: [
      {
        tag: 'release-177',
        previous_tag: 'release-176',
        published_at: '2026-07-24T06:48:51Z',
        deployed_at: '2026-07-24T07:15:03+00:00',
        html_url: 'https://github.com/bsgip/cactus-deploy/releases/tag/release-177',
        components: [
          {
            name: 'Orchestrator',
            repo: 'bsgip/cactus-orchestrator',
            previous: 'v2.2.0',
            current: 'v2.2.1',
            changed: true,
            changes: [
              { title: 'Add .well-known route to traefik', pr: 185, url: 'https://example.com/pull/185' },
            ],
            notes: [],
          },
          {
            name: 'Web UI',
            repo: 'bsgip/cactus-ui',
            previous: 'v2.1.0',
            current: 'v2.1.0',
            changed: false,
            changes: [],
            notes: [],
          },
        ],
        test_definitions: null,
        warnings: [],
      },
    ],
    deploy_history: [{ release_tag: '177', created_at: '2026-07-24T07:15:03+00:00' }],
    ...overrides,
  };
}

describe('release notes page', () => {
  it('renders the newest release expanded with its changed components', async () => {
    server.use(http.get('/api/release-notes', () => HttpResponse.json(makeResponse())));

    renderApp('/release-notes');

    expect(await screen.findByRole('heading', { name: 'Release Notes' })).toBeInTheDocument();
    expect(await screen.findByText('release-177')).toBeInTheDocument();

    const details = document.querySelector('details') as HTMLDetailsElement;
    expect(details.open).toBe(true);

    expect(within(details).getByText('Add .well-known route to traefik')).toBeInTheDocument();
    expect(within(details).getByText('1 repositories unchanged')).toBeInTheDocument();
  });

  it('shows an empty state with a link to GitHub when there are no releases', async () => {
    server.use(http.get('/api/release-notes', () => HttpResponse.json(makeResponse({ releases: [] }))));

    renderApp('/release-notes');

    expect(await screen.findByText(/No release notes to show yet/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'View releases on GitHub' })).toHaveAttribute(
      'href',
      'https://github.com/bsgip/cactus-deploy/releases'
    );
  });

  it('shows a release-level warning callout', async () => {
    server.use(
      http.get('/api/release-notes', () =>
        HttpResponse.json(
          makeResponse({
            releases: [
              {
                ...makeResponse().releases[0],
                warnings: ['Unrecognised key in versions.lock: FOO_VERSION'],
              },
            ],
          })
        )
      )
    );

    renderApp('/release-notes');

    expect(await screen.findByText('Unrecognised key in versions.lock: FOO_VERSION')).toBeInTheDocument();
  });
});
