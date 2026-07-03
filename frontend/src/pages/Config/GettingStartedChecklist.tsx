import { Box, Flex, Text } from '@radix-ui/themes';
import { IconCircle, IconCircleCheck } from '@tabler/icons-react';
import type { RunGroupResponse } from '../../api/types';

// Tinted alert box (Callout.Text renders as <p>, which can't hold the block-level rows below).
function AlertBox({ children }: { children: React.ReactNode }) {
  return (
    <Box
      role="status"
      style={{
        backgroundColor: 'var(--blue-3)',
        border: '1px solid var(--blue-6)',
        borderRadius: 'var(--radius-3)',
        padding: 'var(--space-3)',
      }}
    >
      {children}
    </Box>
  );
}

function ChecklistRow({ done, children }: { done: boolean; children: React.ReactNode }) {
  return (
    <Flex align="center" gap="2">
      {done ? (
        <IconCircleCheck
          size={16}
          role="img"
          aria-label="Done"
          color="var(--green-9)"
          style={{ flexShrink: 0 }}
        />
      ) : (
        <IconCircle
          size={16}
          role="img"
          aria-label="To do"
          color="var(--gray-8)"
          style={{ flexShrink: 0 }}
        />
      )}
      <Text size="2" color={done ? undefined : 'gray'}>
        {children}
      </Text>
    </Flex>
  );
}

// Data-driven getting-started checklist: identity -> run group -> certificate. Hidden once
// both a run group and a certificate exist, since the page is self-explanatory from there.
export function GettingStartedChecklist({
  pen,
  domain,
  runGroups,
}: {
  pen: number | null;
  domain: string;
  runGroups: RunGroupResponse[];
}) {
  const hasIdentity = pen != null || domain !== '';
  const hasRunGroup = runGroups.length > 0;
  const hasCertificate = runGroups.some((rg) => rg.certificate_id != null);

  if (hasRunGroup && hasCertificate) return null;

  return (
    <AlertBox>
      <Flex direction="column" gap="2">
        <Text weight="bold">Getting started</Text>
        <ChecklistRow done={hasIdentity}>
          Set your organisation identity <Text color="gray">(optional)</Text>
        </ChecklistRow>
        <ChecklistRow done={hasRunGroup}>
          Create a run group for the device or client you&apos;re certifying
        </ChecklistRow>
        <ChecklistRow done={hasCertificate}>
          Generate a device or aggregator certificate for it
        </ChecklistRow>
        <Text size="1" color="gray">
          Use the (i) icons for more detail on each step.
        </Text>
      </Flex>
    </AlertBox>
  );
}
