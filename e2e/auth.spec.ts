import { test, expect, type Page } from '@playwright/test';
import { baseURL } from './helpers';

async function signupAndVerify(page: Page, email: string, password: string) {
  await page.goto(`${baseURL()}/signup`);
  await page.fill('input[name="email"]', email);
  await page.fill('input[name="password"]', password);
  await page.click('button[type="submit"]');
  await page.waitForURL('**/check-email**');
  await expect(page.locator('text=Check your inbox')).toBeVisible();
}

test.describe('Signup', () => {
  test('shows signup page', async ({ page }) => {
    await page.goto(`${baseURL()}/signup`);
    await expect(page.locator('h1')).toHaveText('Create your account');
    await expect(page.locator('input[name="email"]')).toBeVisible();
    await expect(page.locator('input[name="password"]')).toBeVisible();
  });

  test('valid signup redirects to check-email', async ({ page }) => {
    await signupAndVerify(page, `e2e-signup-${Date.now()}@example.com`, 'password123');
  });

  test('duplicate email shows error', async ({ page }) => {
    const email = `e2e-dup-${Date.now()}@example.com`;
    await signupAndVerify(page, email, 'password123');
    await page.goto(`${baseURL()}/signup`);
    await page.fill('input[name="email"]', email);
    await page.fill('input[name="password"]', 'password123');
    await page.click('button[type="submit"]');
    await expect(page.locator('.error')).toBeVisible();
  });

  test('weak password shows error', async ({ request }) => {
    const res = await request.post(`${baseURL()}/signup-form`, {
      form: { email: `e2e-weak-${Date.now()}@example.com`, password: 'short' },
    });
    const html = await res.text();
    expect(html).toContain('at least 8 characters');
  });

  test('social login buttons are present', async ({ page }) => {
    await page.goto(`${baseURL()}/signup`);
    await expect(page.locator('text=Continue with Google')).toBeVisible();
    await expect(page.locator('text=Continue with GitHub')).toBeVisible();
  });

  test('login link is present', async ({ page }) => {
    await page.goto(`${baseURL()}/signup`);
    await expect(page.locator('a[href="/login"]')).toBeVisible();
  });
});

test.describe('Login', () => {
  test('shows login page', async ({ page }) => {
    await page.goto(`${baseURL()}/login`);
    await expect(page.locator('h1')).toHaveText('Log in to your account');
    await expect(page.locator('input[name="email"]')).toBeVisible();
    await expect(page.locator('input[name="password"]')).toBeVisible();
  });

  test('wrong password shows error', async ({ page }) => {
    await page.goto(`${baseURL()}/login`);
    await page.fill('input[name="email"]', 'nonexistent@example.com');
    await page.fill('input[name="password"]', 'wrongpassword');
    await page.click('button[type="submit"]');
    await expect(page.locator('.error')).toBeVisible();
  });

  test('forgot password link is present', async ({ page }) => {
    await page.goto(`${baseURL()}/login`);
    await expect(page.locator('a[href="/forgot-password"]')).toBeVisible();
  });

  test('social login buttons are present', async ({ page }) => {
    await page.goto(`${baseURL()}/login`);
    await expect(page.locator('text=Continue with Google')).toBeVisible();
    await expect(page.locator('text=Continue with GitHub')).toBeVisible();
  });

  test('signup link is present', async ({ page }) => {
    await page.goto(`${baseURL()}/login`);
    await expect(page.locator('a[href="/signup"]')).toBeVisible();
  });
});

test.describe('Forgot Password', () => {
  test('shows forgot password page', async ({ page }) => {
    await page.goto(`${baseURL()}/forgot-password`);
    await expect(page.locator('h1')).toHaveText('Reset your password');
    await expect(page.locator('input[name="email"]')).toBeVisible();
  });

  test('submit shows success message', async ({ request }) => {
    const res = await request.post(`${baseURL()}/forgot-password-form`, {
      form: { email: 'anyone@example.com' },
    });
    const html = await res.text();
    expect(html).toContain("we've sent a reset link");
  });

  test('back to login link is present', async ({ page }) => {
    await page.goto(`${baseURL()}/forgot-password`);
    await expect(page.locator('a[href="/login"]')).toBeVisible();
  });
});

test.describe('Verify Email', () => {
  test('invalid token shows error on login page', async ({ page }) => {
    await page.goto(`${baseURL()}/verify?token=invalid-token`);
    // Invalid token renders login.html with error message
    await expect(page.locator('text=Invalid verification link')).toBeVisible();
  });
});

test.describe('UI Design', () => {
  test('signup page has dark theme colors', async ({ page }) => {
    await page.goto(`${baseURL()}/signup`);
    const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    expect(bg).toBe('rgb(15, 19, 25)');
  });

  test('login page has dark theme colors', async ({ page }) => {
    await page.goto(`${baseURL()}/login`);
    const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    expect(bg).toBe('rgb(15, 19, 25)');
  });
});

test.describe('Root Route', () => {
  test('GET / redirects to /login', async ({ page }) => {
    await page.goto(`${baseURL()}/`);
    await expect(page).toHaveURL(/\/login/);
    await expect(page.locator('h1')).toHaveText('Log in to your account');
  });

  test('GET /unknown returns 404', async ({ request }) => {
    const res = await request.get(`${baseURL()}/nonexistent-page`);
    expect(res.status()).toBe(404);
  });
});

test('health endpoint returns ok', async ({ request }) => {
  const res = await request.get(`${baseURL()}/health`);
  expect(res.ok()).toBeTruthy();
  expect(await res.text()).toBe('ok');
});

test('openid-configuration returns valid document', async ({ request }) => {
  const res = await request.get(`${baseURL()}/.well-known/openid-configuration`);
  expect(res.ok()).toBeTruthy();
  const doc = await res.json();
  expect(doc.issuer).toBeTruthy();
  expect(doc.authorization_endpoint).toBeTruthy();
  expect(doc.token_endpoint).toBeTruthy();
  expect(doc.jwks_uri).toBeTruthy();
});

test('jwks returns keys', async ({ request }) => {
  const res = await request.get(`${baseURL()}/jwks.json`);
  expect(res.ok()).toBeTruthy();
  const doc = await res.json();
  expect(doc.keys).toBeDefined();
  expect(doc.keys.length).toBeGreaterThan(0);
  expect(doc.keys[0].kty).toBe('RSA');
});
