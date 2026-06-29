import { Box, Flex, Heading, Separator } from '@radix-ui/themes';
import type { ReactNode } from 'react';

interface SectionCardProps {
  // Plain string renders as the bold heading; pass a node for a custom header row.
  title: ReactNode;
  // Optional icon shown to the left of a string title.
  icon?: ReactNode;
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

// A bordered card with a titled header strip and a full-width separator. Replaces the repeated
// "panel with a heading bar" pattern (was Mantine's Card.Section).
export function SectionCard({ title, icon, action, children, h, scroll }: SectionCardProps) {
  return (
    <Box
      style={{
        height: h,
        border: '1px solid var(--gray-5)',
        borderRadius: 'var(--radius-3)',
        overflow: 'hidden',
        backgroundColor: 'var(--color-panel-solid)',
      }}
    >
      <Flex justify="between" align="center" px="3" py="2">
        {typeof title === 'string' ? (
          <Flex align="center" gap="2">
            {icon}
            <Heading as="h3" size="3">
              {title}
            </Heading>
          </Flex>
        ) : (
          title
        )}
        {action}
      </Flex>
      <Separator size="4" />
      <Box px="3" py="3" style={scroll ? { maxHeight: SCROLL_MAX_HEIGHT, overflowY: 'auto' } : undefined}>
        {children}
      </Box>
    </Box>
  );
}
