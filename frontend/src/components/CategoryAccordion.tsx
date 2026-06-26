import type { ReactNode } from 'react';
import classes from './categoryAccordion.module.css';

// Native <details> accordion with an accent-colored category header. Shared by the Runs
// procedure list and the Playlists test library so the two stay visually consistent.
export function CategoryAccordion({
  title,
  children,
  defaultOpen = true,
}: {
  title: ReactNode;
  children: ReactNode;
  defaultOpen?: boolean;
}) {
  return (
    <details open={defaultOpen} className={classes.item}>
      <summary className={classes.control}>{title}</summary>
      {children}
    </details>
  );
}
