import { Callout, Flex, IconButton } from '@radix-ui/themes';
import { IconAlertTriangle, IconX } from '@tabler/icons-react';
import { useState } from 'react';

// Dismissible warning alert. The message comes from the BANNER_MESSAGE envvar and
// may contain HTML, so it's rendered via dangerouslySetInnerHTML.
export function Banner({ message }: { message: string | null | undefined }) {
  const [dismissed, setDismissed] = useState(false);

  if (!message || dismissed) {
    return null;
  }

  return (
    <Callout.Root color="amber" role="alert" mb="3">
      <Flex justify="between" align="center" gap="3">
        <Flex gap="2" align="center">
          <Callout.Icon>
            <IconAlertTriangle size={16} />
          </Callout.Icon>
          <Callout.Text>
            <span dangerouslySetInnerHTML={{ __html: message }} />
          </Callout.Text>
        </Flex>
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
    </Callout.Root>
  );
}
