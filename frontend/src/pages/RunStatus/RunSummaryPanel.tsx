import { Badge, Dialog, Flex, Table, Text } from '@radix-ui/themes';
import { IconAlertTriangle } from '@tabler/icons-react';
import { useState } from 'react';
import type { RunResponse, WarningEntry } from '../../api/types';
import { SectionCard } from '../../components/SectionCard';
import { formatDate } from '../../utils/dates';

interface Props {
  run: RunResponse;
}

function ResultText({ run }: { run: RunResponse }) {
  if (run.all_criteria_met === true) {
    return <Text color="green">Passed</Text>;
  }
  if (run.all_criteria_met === false) {
    return <Text color="red">Failed</Text>;
  }
  return <Text color="gray">Unknown</Text>;
}

// Run-level metadata that's otherwise only visible by downloading the artifact zip/PDF —
// surfaced directly on the run status page so a glance is enough.
export function RunSummaryPanel({ run }: Props) {
  const [openWarning, setOpenWarning] = useState<WarningEntry | null>(null);
  const warnings = run.warnings ?? [];

  return (
    <SectionCard
      title="Run Summary"
      action={
        warnings.length > 0 ? (
          <Badge color="amber">
            <IconAlertTriangle size={12} /> {warnings.length} warning
            {warnings.length === 1 ? '' : 's'}
          </Badge>
        ) : undefined
      }
    >
      <Table.Root>
        <Table.Body>
          <Table.Row>
            <Table.RowHeaderCell>Test Procedure</Table.RowHeaderCell>
            <Table.Cell>{run.test_procedure_id}</Table.Cell>
          </Table.Row>
          <Table.Row>
            <Table.RowHeaderCell>Result</Table.RowHeaderCell>
            <Table.Cell>
              <ResultText run={run} />
            </Table.Cell>
          </Table.Row>
          <Table.Row>
            <Table.RowHeaderCell>Created</Table.RowHeaderCell>
            <Table.Cell>{formatDate(new Date(run.created_at))}</Table.Cell>
          </Table.Row>
          <Table.Row>
            <Table.RowHeaderCell>Finalised</Table.RowHeaderCell>
            <Table.Cell>
              {run.finalised_at ? (
                formatDate(new Date(run.finalised_at))
              ) : (
                <Text color="gray">Not yet finalised</Text>
              )}
            </Table.Cell>
          </Table.Row>
          <Table.Row>
            <Table.RowHeaderCell>Certificate</Table.RowHeaderCell>
            <Table.Cell>{run.is_device_cert ? 'Device certificate' : 'Aggregator certificate'}</Table.Cell>
          </Table.Row>
          <Table.Row>
            <Table.RowHeaderCell>Compliance Classes</Table.RowHeaderCell>
            <Table.Cell>
              {run.classes && run.classes.length > 0 ? (
                run.classes.map((c) => (
                  <Badge key={c} color="gray" mr="1">
                    {c}
                  </Badge>
                ))
              ) : (
                <Text color="gray">None</Text>
              )}
            </Table.Cell>
          </Table.Row>
        </Table.Body>
      </Table.Root>

      {warnings.length > 0 && (
        <>
          <Text as="p" weight="medium" mt="4" mb="2">
            Warnings
          </Text>
          <Table.Root>
            <Table.Body>
              {warnings.map((w) => (
                <Table.Row
                  key={w.type}
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
        </>
      )}

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
    </SectionCard>
  );
}
