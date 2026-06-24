import { Card, Text } from '@mantine/core';
import type { ReactNode } from 'react';

export function SummaryCard({ value, label, sub }: { value: ReactNode; label: string; sub?: string }) {
  return (
    <Card ta="center">
      <Text fz="xl" fw={700}>
        {value}
      </Text>
      <Text size="sm" c="dimmed">
        {label}
      </Text>
      {sub && (
        <Text size="xs" c="dimmed">
          {sub}
        </Text>
      )}
    </Card>
  );
}
