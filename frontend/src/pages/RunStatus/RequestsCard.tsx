import { Badge, Button, Table, Title } from '@mantine/core';
import { ScrollCard } from '../../components/ScrollCard';
import type { RequestEntry } from '../../api/types';
import { formatDate } from '../../utils/dates';

const MAX_VISIBLE_REQUESTS = 50;

interface Props {
  requests: RequestEntry[];
  onShowRequest: (requestId: number) => void;
}

function statusColor(status: number) {
  return status < 200 || status > 299 ? 'red' : 'green';
}

// "CSIP-Aus Requests" card: the last 50 proxied requests, each opening a details modal.
// Ported from run_status.html requestsTableBody.
export function RequestsCard({ requests, onShowRequest }: Props) {
  const recent = requests.slice(-MAX_VISIBLE_REQUESTS);

  return (
    <ScrollCard header={<Title order={5}>CSIP-Aus Requests</Title>}>
      <Table>
        <Table.Tbody>
          {requests.length === 0 ? (
            <Table.Tr>
              <Table.Th>No requests received</Table.Th>
              <Table.Td />
              <Table.Td />
              <Table.Td />
              <Table.Td />
            </Table.Tr>
          ) : (
            <>
              {requests.length > MAX_VISIBLE_REQUESTS && (
                <Table.Tr>
                  <Table.Td colSpan={5} ta="center" c="dimmed">
                    Showing last {MAX_VISIBLE_REQUESTS} of {requests.length} requests
                  </Table.Td>
                </Table.Tr>
              )}
              {recent.map((r) => {
                const schemaError = r.body_xml_errors.length > 0;
                return (
                  <Table.Tr key={r.request_id}>
                    <Table.Th>{formatDate(new Date(r.timestamp))}</Table.Th>
                    <Table.Td>
                      {r.method} {r.path} <Badge color={statusColor(r.status)}>{r.status}</Badge>
                    </Table.Td>
                    <Table.Td>{r.step_name === 'Unmatched' ? '' : r.step_name}</Table.Td>
                    <Table.Td>
                      <Badge color={schemaError ? 'red' : 'green'}>
                        {schemaError ? 'XSD Errors' : 'XSD Valid'}
                      </Badge>
                    </Table.Td>
                    <Table.Td>
                      <Button
                        size="xs"
                        variant="outline"
                        onClick={() => onShowRequest(r.request_id)}
                      >
                        Details
                      </Button>
                    </Table.Td>
                  </Table.Tr>
                );
              })}
            </>
          )}
        </Table.Tbody>
      </Table>
    </ScrollCard>
  );
}
