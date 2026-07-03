import { screen, waitFor } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';
import { server } from './msw-server';
import { renderApp } from './test-utils';

describe('procedure yaml page', () => {
  it('renders the highlighted YAML from the fixture', async () => {
    renderApp('/procedure/ALL-01');

    expect(
      await screen.findByRole('heading', { name: 'Test Procedure ALL-01' })
    ).toBeInTheDocument();
    expect(document.title).toBe('Procedures - CACTUS');

    expect(screen.getByRole('link', { name: 'CACTUS Test Definitions' })).toHaveAttribute(
      'href',
      'https://github.com/bsgip/cactus-test-definitions'
    );

    // Fixture YAML content is rendered inside a highlighted code block
    const code = await waitFor(() => {
      const el = document.querySelector('code.language-yaml');
      expect(el).not.toBeNull();
      return el!;
    });
    expect(code.textContent).toContain('Discovery with Out-of-Band Registration');
    // highlight.js produced markup (not just escaped plain text)
    expect(code.querySelector('.hljs-attr')).not.toBeNull();
  });

  it('shows the error alert with the BFF error message when the fetch fails', async () => {
    server.use(
      http.get('/api/procedure/:testProcedureId', () =>
        HttpResponse.json({ error: "Failed to fetch YAML for test 'ALL-01'." }, { status: 502 })
      )
    );
    renderApp('/procedure/ALL-01');

    expect(await screen.findByText("Failed to fetch YAML for test 'ALL-01'.")).toBeInTheDocument();
  });
});
