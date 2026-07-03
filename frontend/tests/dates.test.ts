import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { formatDate, formatRelativeDate } from '../src/utils/dates';

describe('formatDate', () => {
  it('formats as YYYY-MM-DD HH:MM:SS', () => {
    expect(formatDate(new Date(2026, 5, 11, 9, 5, 3))).toBe('2026-06-11 09:05:03');
  });
});

describe('formatRelativeDate', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(2026, 5, 11, 12, 0, 0));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  const at = (offsetMs: number) => new Date(Date.now() + offsetMs);

  it('uses seconds under 120s', () => {
    expect(formatRelativeDate(at(-30_000))).toMatch(/30 sec/);
  });

  it('uses minutes under 120m', () => {
    expect(formatRelativeDate(at(-30 * 60_000))).toMatch(/30 min/);
  });

  it('uses hours under 48h', () => {
    expect(formatRelativeDate(at(-5 * 3_600_000))).toMatch(/5 hr/);
  });

  it('uses days beyond 48h', () => {
    expect(formatRelativeDate(at(-3 * 86_400_000))).toMatch(/3 days/);
  });

  it('handles future dates', () => {
    expect(formatRelativeDate(at(90_000))).toMatch(/in 90 sec/);
  });
});
