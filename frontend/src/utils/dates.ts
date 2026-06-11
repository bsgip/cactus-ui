// Ported from src/cactus_ui/static/js/index.js — keep output identical.

const RELATIVE_FORMATTER = new Intl.RelativeTimeFormat('en', { numeric: 'auto', style: 'short' });

export function formatRelativeDate(d: Date): string {
  const now = new Date();
  const diffSeconds = Math.floor((d.getTime() - now.getTime()) / 1000);
  const diffMinutes = Math.floor(diffSeconds / 60);
  const diffHours = Math.floor(diffMinutes / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (Math.abs(diffSeconds) < 120) {
    return RELATIVE_FORMATTER.format(diffSeconds, 'second');
  } else if (Math.abs(diffMinutes) < 120) {
    return RELATIVE_FORMATTER.format(diffMinutes, 'minute');
  } else if (Math.abs(diffHours) < 48) {
    return RELATIVE_FORMATTER.format(diffHours, 'hour');
  } else {
    return RELATIVE_FORMATTER.format(diffDays, 'day');
  }
}

export function formatDate(d: Date): string {
  return d.toLocaleString('sv'); // Sweden format is YYYY-MM-DD HH:MM:SS
}
