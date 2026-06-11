import { expect, test } from '@playwright/test';
import proceduresFixture from '../fixtures/procedures.json' with { type: 'json' };

// Runs against `npm run dev:mock` (MSW serving checked-in fixtures, no backend).

test('procedure yaml page renders the highlighted definition', async ({ page }) => {
  await page.goto('/procedure/ALL-01');

  await expect(page.getByRole('heading', { name: 'Test Procedure ALL-01' })).toBeVisible();
  await expect(page).toHaveTitle('Procedures - CACTUS');

  await expect(page.getByRole('link', { name: 'CACTUS Test Definitions' })).toHaveAttribute(
    'href',
    'https://github.com/bsgip/cactus-test-definitions'
  );

  const code = page.locator('code.language-yaml');
  await expect(code).toContainText('Discovery with Out-of-Band Registration');
  // highlight.js produced markup
  await expect(code.locator('.hljs-attr').first()).toBeVisible();

  await page.screenshot({ path: 'e2e/screenshots/procedure-yaml.png', fullPage: true });
});

test('procedures table links to the yaml page client-side', async ({ page }) => {
  await page.goto('/procedures');
  const first = proceduresFixture.procedures[0];

  let sawNavigationRequest = false;
  page.on('request', (request) => {
    if (request.isNavigationRequest() && request.url().includes('/procedure/')) {
      sawNavigationRequest = true;
    }
  });

  await page.getByRole('link', { name: first.test_procedure_id, exact: true }).click();

  await expect(
    page.getByRole('heading', { name: `Test Procedure ${first.test_procedure_id}` })
  ).toBeVisible();
  expect(sawNavigationRequest).toBe(false);
});
