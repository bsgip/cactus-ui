import { Box, Flex, IconButton, Text } from '@radix-ui/themes';
import { IconX } from '@tabler/icons-react';
import { useState } from 'react';

// Dismissible warning alert. The message comes from the BANNER_MESSAGE envvar and
// may contain HTML, so it's rendered via dangerouslySetInnerHTML.
export function Banner({ message }: { message: string | null | undefined }) {
  const [dismissed, setDismissed] = useState(false);

  if (!message || dismissed) {
    return null;
  }

  return (
    <Box
      role="alert"
      mb="3"
      style={{
        backgroundColor: 'var(--yellow-3)',
        border: '1px solid var(--yellow-6)',
        borderRadius: 'var(--radius-3)',
        padding: 'var(--space-3)',
      }}
    >
      <Flex justify="between" align="center" gap="3">
        <Text size="2">
          <span dangerouslySetInnerHTML={{ __html: message }} />
        </Text>
        <IconButton
          variant="ghost"
          color="gray"
          size="1"
          aria-label="Dismiss"
          onClick={() => setDismissed(true)}
        >
          <IconX size={16} />
        </IconButton>
      </Flex>
    </Box>
  );
}
