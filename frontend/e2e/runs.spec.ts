import { expect, test } from '@playwright/test';
import activeRunsFixture from '../fixtures/active_runs.json' with { type: 'json' };
import procedureRunsFixture from '../fixtures/procedure_runs.json' with { type: 'json' };

// Runs against `npm run dev:mock` (MSW serving checked-in fixtures, no backend).

test('/runs redirects to the first run group and shows active runs', async ({ page }) => {
  await page.goto('/runs');

  await expect(page).toHaveURL('/group/1/runs');
  await expect(page).toHaveTitle('Runs - CACTUS');
  await expect(page.getByRole('heading', { name: 'Runs for' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Active Runs' })).toBeVisible();

  // Active runs rows with links to the (still Flask-rendered) run status page
  for (const run of activeRunsFixture.items) {
    await expect(page.getByRole('link', { name: String(run.run_id), exact: true })).toHaveAttribute(
      'href',
      `/run/${run.run_id}`
    );
  }

  await page.screenshot({ path: 'e2e/screenshots/runs-active.png', fullPage: true });
});

test('selecting a procedure shows its runs and lifecycle controls', async ({ page }) => {
  await page.goto('/group/1/runs');

  await page.getByRole('button', { name: /ALL-01/ }).click();

  await expect(page.getByRole('link', { name: 'ALL-01', exact: true })).toHaveAttribute(
    'href',
    '/procedure/ALL-01'
  );
  await expect(page.getByRole('button', { name: 'New Test Run' })).toBeVisible();

  // One row per fixture run; Start for the initialised run, Download for artifact runs
  await expect(page.getByRole('row')).toHaveCount(procedureRunsFixture.items.length);
  await expect(page.getByRole('button', { name: 'Start' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Download' }).first()).toHaveAttribute(
    'href',
    '/run/120/artifact'
  );

  await page.screenshot({ path: 'e2e/screenshots/runs-procedure.png', fullPage: true });
});

test('compliance class filter hides procedures', async ({ page }) => {
  await page.goto('/group/1/runs');

  await expect(page.getByText('Showing ALL compliance classes')).toBeVisible();
  await page.getByRole('button', { name: 'Filter compliance classes' }).click();
  await page.getByRole('button', { name: 'Select NONE' }).click();

  await expect(page.getByText('Showing NO compliance classes')).toBeVisible();
  await expect(page.getByRole('button', { name: /ALL-01/ })).toHaveCount(0);
});

test('admin view gates the lifecycle controls', async ({ page }) => {
  await page.goto('/admin/group/1/runs');

  await expect(page.getByRole('button', { name: 'Running...' }).first()).toBeDisabled();
  await expect(page.getByRole('button', { name: /Delete run/ })).toHaveCount(0);
  await expect(page.getByRole('link', { name: '123', exact: true })).toHaveAttribute(
    'href',
    '/admin/run/123'
  );
});

test('NavBar navigates to runs client-side', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Welcome to CACTUS' })).toBeVisible();

  let sawNavigationRequest = false;
  page.on('request', (request) => {
    if (request.isNavigationRequest() && request.url().includes('/runs')) {
      sawNavigationRequest = true;
    }
  });

  await page.getByRole('link', { name: 'Runs', exact: true }).click();

  await expect(page.getByRole('heading', { name: 'Runs for' })).toBeVisible();
  expect(sawNavigationRequest).toBe(false);
});
