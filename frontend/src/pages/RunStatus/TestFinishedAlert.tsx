import { Box, Flex, Text } from '@radix-ui/themes';
import { IconCircleCheck } from '@tabler/icons-react';

// Shown once the runner reports the test as finished (`timestamp_finished` set) but the run
// hasn't been finalised yet. Older runners that predate the field never set it, so this alert
// simply never appears for them. Informational only — the header card's Finalise button
// remains the one place to act, avoiding a second identical button on the page.
export function TestFinishedAlert() {
  return (
    <Box
      role="alert"
      style={{
        backgroundColor: 'var(--green-3)',
        border: '1px solid var(--green-6)',
        borderRadius: 'var(--radius-3)',
        padding: 'var(--space-3)',
      }}
    >
      <Flex gap="3" align="center">
        <IconCircleCheck size={18} color="var(--green-9)" style={{ flexShrink: 0 }} />
        <Text weight="bold">This test has finished — press Finalise above when ready</Text>
      </Flex>
    </Box>
  );
}
