import { Card, Text } from '@radix-ui/themes';
import type { ReactNode } from 'react';

export function SummaryCard({ value, label, sub }: { value: ReactNode; label: string; sub?: string }) {
  return (
    <Card style={{ textAlign: 'center' }}>
      <Text as="div" size="5" weight="bold">
        {value}
      </Text>
      <Text as="div" size="2" color="gray">
        {label}
      </Text>
      {sub && (
        <Text as="div" size="1" color="gray">
          {sub}
        </Text>
      )}
    </Card>
  );
}
