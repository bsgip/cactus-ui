import { Button, Code, Group, Table, Title } from '@mantine/core';
import { ScrollCard } from '../../components/ScrollCard';
import { useState } from 'react';
import type { RequestEntry } from '../../api/types';
import { formatDate, formatRelativeDate } from '../../utils/dates';
import { xsdErrorRequests } from './statusHelpers';

const MAX_ERROR_LENGTH = 500;

interface Props {
  requests: RequestEntry[];
  onShowRequest: (requestId: number) => void;
}

function truncate(error: string): string {
  return error.length <= MAX_ERROR_LENGTH
    ? error
    : `${error.substring(0, MAX_ERROR_LENGTH)}... (truncated)`;
}

function title(shownCount: number, totalCount: number): string {
  if (shownCount <= 1) return 'Latest XSD Validation Error';
  if (totalCount > 10) return `Latest XSD Validation Errors: Showing 10/${totalCount}`;
  return 'Latest XSD Validation Errors';
}

// "XSD Validation Errors" panel: the 10 most recent requests that failed schema validation,
// with prev/next navigation. Ported from run_status.html xsdTableBody + cycleXsdError.
export function XsdErrorsCard({ requests, onShowRequest }: Props) {
  const [index, setIndex] = useState(0);
  const withErrors = xsdErrorRequests(requests);
  const totalErrorCount = requests.filter((r) => r.body_xml_errors.length > 0).length;

  // Clamp the cursor if the error list shrank between polls.
  const currentIndex = Math.min(index, Math.max(0, withErrors.length - 1));
  const current = withErrors[currentIndex];

  return (
    <ScrollCard
      header={
        <Group justify="space-between">
          <Title order={5}>{title(withErrors.length, totalErrorCount)}</Title>
          {withErrors.length > 1 && (
            <Group gap="xs">
              <Button
                size="xs"
                variant="outline"
                disabled={currentIndex === 0}
                onClick={() => setIndex(currentIndex - 1)}
              >
                ← Previous
              </Button>
              <Button size="xs" variant="outline" color="gray" disabled>
                {currentIndex + 1} of {withErrors.length}
              </Button>
              <Button
                size="xs"
                variant="outline"
                disabled={currentIndex === withErrors.length - 1}
                onClick={() => setIndex(currentIndex + 1)}
              >
                Next →
              </Button>
            </Group>
          )}
        </Group>
      }
    >
      <Table>
        <Table.Tbody>
          {!current ? (
            <Table.Tr>
              <Table.Td colSpan={2} ta="center" c="dimmed">
                No XSD validation errors detected
              </Table.Td>
            </Table.Tr>
          ) : (
            <>
              <Table.Tr>
                <Table.Th>Timestamp</Table.Th>
                <Table.Td>
                  {formatDate(new Date(current.timestamp))} (
                  {formatRelativeDate(new Date(current.timestamp))})
                </Table.Td>
              </Table.Tr>
              <Table.Tr>
                <Table.Th>Request</Table.Th>
                <Table.Td>
                  {current.method} {current.path}
                </Table.Td>
              </Table.Tr>
              <Table.Tr>
                <Table.Th>URL</Table.Th>
                <Table.Td>
                  <Code style={{ wordBreak: 'break-all' }}>{current.url}</Code>
                </Table.Td>
              </Table.Tr>
              <Table.Tr>
                <Table.Th>Step</Table.Th>
                <Table.Td>
                  {current.step_name === 'Unmatched' ? <em>Unmatched</em> : current.step_name}
                </Table.Td>
              </Table.Tr>
              <Table.Tr>
                <Table.Th>XSD Errors</Table.Th>
                <Table.Td>
                  <ul style={{ margin: 0, maxHeight: 300, overflowY: 'auto' }}>
                    {current.body_xml_errors.map((err, i) => (
                      <li key={i}>
                        <Code style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                          {truncate(err)}
                        </Code>
                      </li>
                    ))}
                  </ul>
                </Table.Td>
              </Table.Tr>
              <Table.Tr>
                <Table.Th>Details</Table.Th>
                <Table.Td>
                  <Button size="xs" onClick={() => onShowRequest(current.request_id)}>
                    View Full Request Details
                  </Button>
                </Table.Td>
              </Table.Tr>
            </>
          )}
        </Table.Tbody>
      </Table>
    </ScrollCard>
  );
}
