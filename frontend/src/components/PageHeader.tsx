import { Flex, Heading } from '@radix-ui/themes';
import type { ReactNode } from 'react';

// Standard page heading row: an <h2> title with optional right-aligned actions.
// Carries no outer margin — the page lays out spacing (usually a column Flex).
export function PageHeader({ title, children }: { title: ReactNode; children?: ReactNode }) {
  return (
    <Flex justify="between" align="center">
      <Heading as="h2" size="6">
        {title}
      </Heading>
      {children}
    </Flex>
  );
}
