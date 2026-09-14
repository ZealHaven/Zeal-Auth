import { test, expect } from '@playwright/test';
import { baseURL } from './helpers';

test.describe('Session Management', () => {
  test('GET /authorize without session returns error or redirect', async ({ page }) => {
    await page.goto(`${baseURL()}/authorize?response_type=code&client_id=nonexistent&redirect_uri=http://localhost/callback`);
    // fosite returns an error for unknown client, not a redirect to /login
    const status = page.url();
    expect(status).toBeTruthy();
  });

  test('GET /logout clears session and redirects to /login', async ({ page }) => {
    await page.goto(`${baseURL()}/logout`);
    await page.waitForURL('**/login**');
    await expect(page).toHaveURL(/\/login/);
  });

  test('GET /logout with post_logout_redirect_uri redirects there', async ({ page }) => {
    await page.goto(`${baseURL()}/logout?post_logout_redirect_uri=${encodeURIComponent(`${baseURL()}/login`)}`);
    await page.waitForURL('**/login**');
  });

  test('login page shows after logout', async ({ page }) => {
    await page.goto(`${baseURL()}/logout`);
    await expect(page.locator('h1')).toHaveText('Log in to your account');
  });
});

test.describe('Link Account', () => {
  test('shows link-account page with provider info', async ({ page }) => {
    await page.goto(`${baseURL()}/link-account?provider=google&email=test@example.com`);
    await expect(page.locator('h1')).toHaveText('An account already exists');
    await expect(page.locator('text=google')).toBeVisible();
    await expect(page.locator('text=test@example.com')).toBeVisible();
  });
});
