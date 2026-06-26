import { Badge, Button, Table } from '@radix-ui/themes';
import { SectionCard } from '../../components/SectionCard';
import type { RequestEntry } from '../../api/types';
import { formatDate } from '../../utils/dates';

const MAX_VISIBLE_REQUESTS = 50;

interface Props {
  requests: RequestEntry[];
  onShowRequest: (requestId: number) => void;
}

function statusColor(status: number): 'red' | 'green' {
  return status < 200 || status > 299 ? 'red' : 'green';
}

// "CSIP-Aus Requests" card: the last 50 proxied requests, each opening a details modal.
export function RequestsCard({ requests, onShowRequest }: Props) {
  const recent = requests.slice(-MAX_VISIBLE_REQUESTS);

  return (
    <SectionCard scroll title="CSIP-Aus Requests">
      <Table.Root>
        <Table.Body>
          {requests.length === 0 ? (
            <Table.Row>
              <Table.RowHeaderCell>No requests received</Table.RowHeaderCell>
              <Table.Cell />
              <Table.Cell />
              <Table.Cell />
              <Table.Cell />
            </Table.Row>
          ) : (
            <>
              {requests.length > MAX_VISIBLE_REQUESTS && (
                <Table.Row>
                  <Table.Cell colSpan={5} style={{ textAlign: 'center', color: 'var(--gray-9)' }}>
                    Showing last {MAX_VISIBLE_REQUESTS} of {requests.length} requests
                  </Table.Cell>
                </Table.Row>
              )}
              {recent.map((r) => {
                const schemaError = r.body_xml_errors.length > 0;
                return (
                  <Table.Row key={r.request_id}>
                    <Table.RowHeaderCell>{formatDate(new Date(r.timestamp))}</Table.RowHeaderCell>
                    <Table.Cell>
                      {r.method} {r.path} <Badge color={statusColor(r.status)}>{r.status}</Badge>
                    </Table.Cell>
                    <Table.Cell>{r.step_name === 'Unmatched' ? '' : r.step_name}</Table.Cell>
                    <Table.Cell>
                      <Badge color={schemaError ? 'red' : 'green'}>
                        {schemaError ? 'XSD Errors' : 'XSD Valid'}
                      </Badge>
                    </Table.Cell>
                    <Table.Cell>
                      <Button size="1" variant="outline" onClick={() => onShowRequest(r.request_id)}>
                        Details
                      </Button>
                    </Table.Cell>
                  </Table.Row>
                );
              })}
            </>
          )}
        </Table.Body>
      </Table.Root>
    </SectionCard>
  );
}
