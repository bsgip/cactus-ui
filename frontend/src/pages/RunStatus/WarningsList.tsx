import { Dialog, Flex, Table, Text } from '@radix-ui/themes';
import { IconAlertTriangle } from '@tabler/icons-react';
import { useState } from 'react';
import type { WarningEntry } from '../../api/types';
import { formatDate } from '../../utils/dates';

// Shared list-with-detail-popup for WarningEntry[], used both on the finalised run summary
// and the live status panels (RunnerStatus.warnings streams mid-run too).
export function WarningsList({ warnings }: { warnings: WarningEntry[] }) {
  const [openWarning, setOpenWarning] = useState<WarningEntry | null>(null);

  if (warnings.length === 0) {
    return <Text color="gray">No warnings</Text>;
  }

  return (
    <>
      <Table.Root>
        <Table.Body>
          {warnings.map((w) => (
            <Table.Row
              key={`${w.type}-${w.timestamp}`}
              style={{ cursor: 'pointer' }}
              onClick={() => setOpenWarning(w)}
            >
              <Table.Cell>
                <Flex align="center" gap="2">
                  <IconAlertTriangle size={14} color="var(--amber-9)" />
                  {w.description}
                </Flex>
              </Table.Cell>
            </Table.Row>
          ))}
        </Table.Body>
      </Table.Root>

      <Dialog.Root open={openWarning !== null} onOpenChange={(o) => !o && setOpenWarning(null)}>
        <Dialog.Content maxWidth="600px">
          <Dialog.Title>{openWarning?.description}</Dialog.Title>
          <Text as="p" mb="2" style={{ whiteSpace: 'pre-wrap' }}>
            {openWarning?.message}
          </Text>
          <Text as="p" size="1" color="gray">
            {openWarning && formatDate(new Date(openWarning.timestamp))}
          </Text>
        </Dialog.Content>
      </Dialog.Root>
    </>
  );
}
