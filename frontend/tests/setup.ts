import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterAll, afterEach, beforeAll, vi } from 'vitest';
import { server } from './msw-server';

// Chart.js renders onto a <canvas>, which jsdom does not implement. Stub react-chartjs-2 so
// the timeline chart mounts without a 2d context; real rendering is covered by Playwright.
vi.mock('react-chartjs-2', () => ({
  Line: () => null,
}));

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => {
  server.resetHandlers();
  cleanup();
});
afterAll(() => server.close());

// jsdom shims for layout/measurement APIs jsdom lacks (used by Radix Themes + Chart.js).
const { getComputedStyle } = window;
window.getComputedStyle = (elt) => getComputedStyle(elt);
window.HTMLElement.prototype.scrollIntoView = () => {};

Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: vi.fn().mockImplementation((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
});

class ResizeObserverShim {
  observe() {}
  unobserve() {}
  disconnect() {}
}
window.ResizeObserver = window.ResizeObserver ?? ResizeObserverShim;

// jsdom has no object URLs; apiDownload needs these to hand blobs to the browser.
window.URL.createObjectURL = window.URL.createObjectURL ?? (() => 'blob:jsdom-stub');
window.URL.revokeObjectURL = window.URL.revokeObjectURL ?? (() => {});
