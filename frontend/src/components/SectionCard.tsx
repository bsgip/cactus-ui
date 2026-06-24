import { Card, Group, Text } from '@mantine/core';
import type { ReactNode } from 'react';

interface SectionCardProps {
  // Plain string renders as the bold heading; pass a node for a custom header row.
  title: ReactNode;
  // Optional right-aligned header content (e.g. a "Show all" button or count badge).
  action?: ReactNode;
  children: ReactNode;
}

// A bordered card with a titled header strip, built from Mantine's native Card.Section
// (no hand-rolled border CSS). Replaces the repeated "panel with a heading bar" pattern.
export function SectionCard({ title, action, children }: SectionCardProps) {
  return (
    <Card padding="md">
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
