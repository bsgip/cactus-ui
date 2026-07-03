import { IconChevronRight } from '@tabler/icons-react';
import type { ReactNode } from 'react';
import classes from './categoryAccordion.module.css';

// Native <details> accordion with a soft accent-tinted header and a rotating chevron. Shared by
// the Runs procedure list and the Playlists test library so the two stay visually consistent.
export function CategoryAccordion({
  title,
  children,
  count,
  defaultOpen = true,
}: {
  title: ReactNode;
  children: ReactNode;
  count?: number;
  defaultOpen?: boolean;
}) {
  return (
    <details open={defaultOpen} className={classes.item}>
      <summary className={classes.control}>
        <IconChevronRight size={16} className={classes.chevron} aria-hidden />
        <span className={classes.title}>{title}</span>
        {count !== undefined && <span className={classes.count}>{count}</span>}
      </summary>
      {children}
    </details>
  );
}
