import { Button, Code, Flex, Table } from '@radix-ui/themes';
import { SectionCard } from '../../components/SectionCard';
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
// with prev/next navigation.
export function XsdErrorsCard({ requests, onShowRequest }: Props) {
  const [index, setIndex] = useState(0);
  const withErrors = xsdErrorRequests(requests);
  const totalErrorCount = requests.filter((r) => r.body_xml_errors.length > 0).length;

  // Clamp the cursor if the error list shrank between polls.
  const currentIndex = Math.min(index, Math.max(0, withErrors.length - 1));
  const current = withErrors[currentIndex];

  return (
    <SectionCard
      scroll
      title={title(withErrors.length, totalErrorCount)}
      action={
        withErrors.length > 1 && (
          <Flex gap="2" align="center">
            <Button
              size="1"
              variant="outline"
              disabled={currentIndex === 0}
              onClick={() => setIndex(currentIndex - 1)}
            >
              ← Previous
            </Button>
            <Button size="1" variant="outline" color="gray" disabled>
              {currentIndex + 1} of {withErrors.length}
            </Button>
            <Button
              size="1"
              variant="outline"
              disabled={currentIndex === withErrors.length - 1}
              onClick={() => setIndex(currentIndex + 1)}
            >
              Next →
            </Button>
          </Flex>
        )
      }
    >
      <Table.Root>
        <Table.Body>
          {!current ? (
            <Table.Row>
              <Table.Cell colSpan={2} style={{ textAlign: 'center', color: 'var(--gray-9)' }}>
                No XSD validation errors detected
              </Table.Cell>
            </Table.Row>
          ) : (
            <>
              <Table.Row>
                <Table.RowHeaderCell>Timestamp</Table.RowHeaderCell>
                <Table.Cell>
                  {formatDate(new Date(current.timestamp))} (
                  {formatRelativeDate(new Date(current.timestamp))})
                </Table.Cell>
              </Table.Row>
              <Table.Row>
                <Table.RowHeaderCell>Request</Table.RowHeaderCell>
                <Table.Cell>
                  {current.method} {current.path}
                </Table.Cell>
              </Table.Row>
              <Table.Row>
                <Table.RowHeaderCell>URL</Table.RowHeaderCell>
                <Table.Cell>
                  <Code style={{ wordBreak: 'break-all' }}>{current.url}</Code>
                </Table.Cell>
              </Table.Row>
              <Table.Row>
                <Table.RowHeaderCell>Step</Table.RowHeaderCell>
                <Table.Cell>
                  {current.step_name === 'Unmatched' ? <em>Unmatched</em> : current.step_name}
                </Table.Cell>
              </Table.Row>
              <Table.Row>
                <Table.RowHeaderCell>XSD Errors</Table.RowHeaderCell>
                <Table.Cell>
                  <ul style={{ margin: 0, maxHeight: 300, overflowY: 'auto' }}>
                    {current.body_xml_errors.map((err, i) => (
                      <li key={i}>
                        <Code style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                          {truncate(err)}
                        </Code>
                      </li>
                    ))}
                  </ul>
                </Table.Cell>
              </Table.Row>
              <Table.Row>
                <Table.RowHeaderCell>Details</Table.RowHeaderCell>
                <Table.Cell>
                  <Button size="1" onClick={() => onShowRequest(current.request_id)}>
                    View Full Request Details
                  </Button>
                </Table.Cell>
              </Table.Row>
            </>
          )}
        </Table.Body>
      </Table.Root>
    </SectionCard>
  );
}
