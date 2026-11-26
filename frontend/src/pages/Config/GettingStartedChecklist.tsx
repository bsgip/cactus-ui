import { Box, Flex, Text } from '@radix-ui/themes';
import { IconInfoCircle, IconCircle, IconCircleCheck } from '@tabler/icons-react';
import type { CertificateResponse, RunGroupResponse } from '../../api/types';

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

// Data-driven getting-started checklist: identity -> run group -> certificate -> assignment.
// Hidden once a run group has a certificate assigned, since the page is self-explanatory from there.
export function GettingStartedChecklist({
  pen,
  domain,
  runGroups,
  certificates,
}: {
  pen: number | null;
  domain: string;
  runGroups: RunGroupResponse[];
  certificates: CertificateResponse[];
}) {
  const hasIdentity = pen != null;
  const hasDomain = domain !== '';
  const hasRunGroup = runGroups.length > 0;
  const hasCertificate = certificates.length > 0;
  const hasAssignment = runGroups.some((rg) => rg.assigned_certificate_id != null);

  if (hasRunGroup && hasAssignment) return null;

  return (
    <AlertBox>
      <Flex direction="column" gap="2">
        <Text weight="bold">Getting started</Text>
        <ChecklistRow done={hasIdentity}>
          Set your organisation identity <Text color="gray">(optional)</Text>
        </ChecklistRow>
        <ChecklistRow done={hasDomain}>
          Set your notification domain <Text color="gray">(optional)</Text>
        </ChecklistRow>
        <ChecklistRow done={hasRunGroup}>
          Create a run group for the device or client you&apos;re certifying
        </ChecklistRow>
        <ChecklistRow done={hasCertificate}>
          Generate a device or aggregator certificate
        </ChecklistRow>
        <ChecklistRow done={hasAssignment}>
          Assign a certificate to your run group
        </ChecklistRow>
        <Text size="1" color="gray">
          Use the <IconInfoCircle size={16} style={{display: "inline", position: "relative", top: "4px"}}/> icons for more detail on each step.
        </Text>
      </Flex>
    </AlertBox>
  );
}
