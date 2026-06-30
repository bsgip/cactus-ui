import { IconButton, Popover, Text } from '@radix-ui/themes';
import { IconInfoCircle } from '@tabler/icons-react';
import type { ReactNode } from 'react';

// A small (i) trigger that opens an optional, in-depth explainer. Used across the config page so
// the dense view stays scannable while still letting users drill into the PKI detail on demand.
export function InfoPopover({
  title,
  label = 'More information',
  children,
}: {
  title?: string;
  label?: string;
  children: ReactNode;
}) {
  return (
    <Popover.Root>
      <Popover.Trigger>
        <IconButton
          type="button"
          size="1"
          variant="ghost"
          color="gray"
          radius="full"
          aria-label={label}
        >
          <IconInfoCircle size={16} />
        </IconButton>
      </Popover.Trigger>
      <Popover.Content size="2" maxWidth="380px">
        {title && (
          <Text as="p" size="2" weight="bold" mb="1">
            {title}
          </Text>
        )}
        <Text as="div" size="2" color="gray">
          {children}
        </Text>
      </Popover.Content>
    </Popover.Root>
  );
}
