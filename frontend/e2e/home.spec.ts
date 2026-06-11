import { expect, test } from '@playwright/test';

// Runs against `npm run dev:mock` (MSW serving checked-in fixtures, no backend).

test('home page renders for a logged-in session', async ({ page }) => {
  await page.goto('/');

  await expect(page.getByRole('heading', { name: 'Welcome to CACTUS' })).toBeVisible();
  await expect(page.getByText('User: Test User')).toBeVisible();
  for (const link of ['Procedures', 'Runs', 'Playlists', 'Config']) {
    await expect(page.getByRole('link', { name: link, exact: true })).toBeVisible();
  }
  await expect(page.getByRole('link', { name: 'Logout' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Admin', exact: true })).not.toBeVisible();
  await expect(page.getByRole('heading', { name: 'Getting Started' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Common Issues' })).toBeVisible();

  await page.screenshot({ path: 'e2e/screenshots/home.png', fullPage: true });
});
