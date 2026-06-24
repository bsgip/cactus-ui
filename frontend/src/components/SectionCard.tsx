import { Card, Group, Text } from '@mantine/core';
import type { ReactNode } from 'react';

interface SectionCardProps {
  // Plain string renders as the bold heading; pass a node for a custom header row.
  title: ReactNode;
  // Optional right-aligned header content (e.g. a "Show all" button or count badge).
  action?: ReactNode;
  children: ReactNode;
  // Card height — e.g. "100%" to equalise cards sharing a Grid row.
  h?: string | number;
  // When true, the body scrolls internally (up to SCROLL_MAX_HEIGHT) while the header stays
  // pinned above it — used by the long, frequently-polled run-status tables.
  scroll?: boolean;
}

const SCROLL_MAX_HEIGHT = 600;

// A bordered card with a titled header strip, built from Mantine's native Card.Section
// (no hand-rolled border CSS). Replaces the repeated "panel with a heading bar" pattern.
export function SectionCard({ title, action, children, h, scroll }: SectionCardProps) {
  return (
    <Card padding="md" h={h}>
      <Card.Section withBorder inheritPadding py="xs">
        <Group justify="space-between">
          {typeof title === 'string' ? <Text fw={700}>{title}</Text> : title}
          {action}
        </Group>
      </Card.Section>
      <Card.Section
        inheritPadding
        py="md"
        mah={scroll ? SCROLL_MAX_HEIGHT : undefined}
        style={scroll ? { overflowY: 'auto' } : undefined}
      >
        {children}
      </Card.Section>
    </Card>
  );
}
