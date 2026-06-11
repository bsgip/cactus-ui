import { expect, test } from '@playwright/test';
import proceduresFixture from '../fixtures/procedures.json' with { type: 'json' };

// Runs against `npm run dev:mock` (MSW serving checked-in fixtures, no backend).

test('procedures page lists every procedure from the fixture', async ({ page }) => {
  await page.goto('/procedures');

  await expect(page.getByRole('heading', { name: 'Test Procedures' })).toBeVisible();
  await expect(page).toHaveTitle('Procedures - CACTUS');

  // Header row + one row per procedure
  await expect(page.getByRole('row')).toHaveCount(proceduresFixture.procedures.length + 1);

  const first = proceduresFixture.procedures[0];
  await expect(
    page.getByRole('link', { name: first.test_procedure_id, exact: true })
  ).toHaveAttribute('href', `/procedure/${first.test_procedure_id}`);

  await page.screenshot({ path: 'e2e/screenshots/procedures.png', fullPage: true });
});

test('NavBar navigates to procedures client-side', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Welcome to CACTUS' })).toBeVisible();

  // A client-side navigation must not trigger a document load
  let sawNavigationRequest = false;
  page.on('request', (request) => {
    if (request.isNavigationRequest() && request.url().includes('/procedures')) {
      sawNavigationRequest = true;
    }
  });

  await page.getByRole('link', { name: 'Procedures', exact: true }).click();

  await expect(page.getByRole('heading', { name: 'Test Procedures' })).toBeVisible();
  expect(sawNavigationRequest).toBe(false);
});
