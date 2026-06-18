import { expect, test } from '@playwright/test';

// Runs against `npm run dev:mock` (MSW serving checked-in fixtures, no backend). The default
// run-status fixtures describe a live "started" run with timeline data, so the chart renders
// against a real canvas here (jsdom can't, so this is the only place the canvas is exercised).

test('live run status page renders the header, panels and timeline chart', async ({ page }) => {
  await page.goto('/run/123');

  await expect(page).toHaveTitle('Run Status 123 - CACTUS');
  await expect(page.getByRole('heading', { name: 'Run 123 (started)' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Finalise' })).toBeEnabled();

  // Live status panels.
  await expect(page.getByText('Precondition Checks')).toBeVisible();
  await expect(page.getByText('Current Criteria')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Timeline' })).toBeVisible();

  // The timeline renders two real <canvas> elements (main chart + activity strip).
  await expect(page.locator('canvas')).toHaveCount(2);
  await expect(page.locator('canvas').first()).toBeVisible();

  await page.screenshot({ path: 'e2e/screenshots/run-status-live.png', fullPage: true });
});

test('admin run status view disables the finalise control', async ({ page }) => {
  await page.goto('/admin/run/123');

  await expect(page.getByRole('heading', { name: 'Run 123 (started)' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Finalise' })).toBeDisabled();
  await expect(page.getByRole('heading', { name: 'Timeline' })).toBeVisible();
});

test('runs table links navigate to the run status page client-side', async ({ page }) => {
  await page.goto('/group/1/runs');

  let sawNavigationRequest = false;
  page.on('request', (request) => {
    if (request.isNavigationRequest() && request.url().includes('/run/')) {
      sawNavigationRequest = true;
    }
  });

  await page.getByRole('link', { name: '123', exact: true }).click();

  await expect(page).toHaveURL('/run/123');
  await expect(page.getByRole('heading', { name: 'Run 123 (started)' })).toBeVisible();
  expect(sawNavigationRequest).toBe(false);
});
