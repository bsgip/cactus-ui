import { Group, Title } from '@mantine/core';
import type { ReactNode } from 'react';

// Standard page heading row: an <h2> title with optional right-aligned actions.
// Carries no outer margin — the page lays out spacing (usually a <Stack>).
export function PageHeader({ title, children }: { title: ReactNode; children?: ReactNode }) {
  return (
    <Group justify="space-between" align="center">
      <Title order={2}>{title}</Title>
      {children}
    </Group>
  );
}
