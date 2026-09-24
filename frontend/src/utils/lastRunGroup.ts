// Remembers the run group the user last viewed on the Runs page so /runs can return them to
// it. Storage may be unavailable (private mode, blocked site data) - every access is
// best-effort and callers fall back to the first run group.
const STORAGE_KEY = 'cactus.lastRunGroupId';

export function getLastRunGroupId(): number | null {
  try {
    const value = Number(window.localStorage.getItem(STORAGE_KEY));
    return Number.isInteger(value) && value > 0 ? value : null;
  } catch {
    return null;
  }
}

export function setLastRunGroupId(runGroupId: number) {
  try {
    window.localStorage.setItem(STORAGE_KEY, String(runGroupId));
  } catch {
    // Ignore - persistence is a convenience only.
  }
}
