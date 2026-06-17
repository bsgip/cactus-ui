import { expect, test } from '@playwright/test';

// Runs against `npm run dev:mock` (MSW serving checked-in fixtures, no backend).

test('/playlists redirects to the first run group and shows the builder', async ({ page }) => {
  await page.goto('/playlists');

  await expect(page).toHaveURL('/group/1/playlists');
  await expect(page).toHaveTitle('Playlists - CACTUS');
  await expect(page.getByRole('button', { name: 'Battery Mk1' })).toBeVisible();
  await expect(page.getByText('Test Library')).toBeVisible();
  await expect(page.getByText('No tests selected.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Start Playlist' })).toBeDisabled();

  await page.screenshot({ path: 'e2e/screenshots/playlists.png', fullPage: true });
});

test('building a queue enables Start Playlist', async ({ page }) => {
  await page.goto('/group/1/playlists');

  await page.getByRole('button', { name: /ALL-01/ }).first().click();

  await expect(page.getByRole('button', { name: /Remove ALL-01/ })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Start Playlist' })).toBeEnabled();

  await page.screenshot({ path: 'e2e/screenshots/playlists-queue.png', fullPage: true });
});

test('shows active and past playlist sessions', async ({ page }) => {
  await page.goto('/group/1/playlists');

  await expect(page.getByText('Active Playlist')).toBeVisible();
  await expect(page.getByRole('link', { name: 'active-e' })).toHaveAttribute('href', '/run/201');
  await expect(page.getByRole('link', { name: /Go to run/ })).toHaveAttribute('href', '/run/202');

  await expect(page.getByText('Past Sessions')).toBeVisible();
  await expect(page.getByRole('link', { name: 'past-exe' })).toHaveAttribute('href', '/run/150');
});

test('NavBar navigates to playlists client-side', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Welcome to CACTUS' })).toBeVisible();

  let sawNavigationRequest = false;
  page.on('request', (request) => {
    if (request.isNavigationRequest() && request.url().includes('/playlists')) {
      sawNavigationRequest = true;
    }
  });

  await page.getByRole('link', { name: 'Playlists', exact: true }).click();

  await expect(page.getByRole('button', { name: 'Battery Mk1' })).toBeVisible();
  expect(sawNavigationRequest).toBe(false);
});
