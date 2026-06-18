import { Box, Card } from '@mantine/core';
import type { ReactNode } from 'react';

interface ScrollCardProps {
  // Header content (usually a Title, or a Group of Title + action buttons). Stays pinned to
  // the top of the card while its body scrolls, so you never lose track of which box you're in.
  header: ReactNode;
  children: ReactNode;
  maxHeight?: number;
}

// A bordered, internally-scrolling card with a sticky header. The Card padding is moved onto
// the header/body boxes so the sticky header can sit flush at top:0 and fully cover the
// content scrolling beneath it (no peek-through past the card's padding).
export function ScrollCard({ header, children, maxHeight = 600 }: ScrollCardProps) {
  return (
    <Card withBorder p={0} style={{ maxHeight, overflowY: 'auto' }}>
      <Box
        px="md"
        pt="md"
        pb="xs"
        style={{
          position: 'sticky',
          top: 0,
          zIndex: 1,
          backgroundColor: 'var(--mantine-color-body)',
          borderBottom: '1px solid var(--mantine-color-gray-2)',
        }}
      >
        {header}
      </Box>
      <Box px="md" pt="sm" pb="md">
        {children}
      </Box>
    </Card>
  );
}
