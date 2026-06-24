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
}

// A bordered card with a titled header strip, built from Mantine's native Card.Section
// (no hand-rolled border CSS). Replaces the repeated "panel with a heading bar" pattern.
export function SectionCard({ title, action, children, h }: SectionCardProps) {
  return (
    <Card padding="md" h={h}>
      <Card.Section withBorder inheritPadding py="xs">
        <Group justify="space-between">
          {typeof title === 'string' ? <Text fw={700}>{title}</Text> : title}
          {action}
        </Group>
      </Card.Section>
      <Card.Section inheritPadding py="md">
        {children}
      </Card.Section>
    </Card>
  );
}
