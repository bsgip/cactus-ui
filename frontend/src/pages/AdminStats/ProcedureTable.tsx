import { Badge, Button, Group, Progress, Table, Text } from '@mantine/core';
import { useState } from 'react';
import type { ProcedureStat } from '../../api/types';
import { SectionCard } from '../../components/SectionCard';

function ProcedureRow({ p }: { p: ProcedureStat }) {
  const assessed = p.latest_passed + p.latest_failed;
  const passPct = assessed > 0 ? Math.round((p.latest_passed / assessed) * 1000) / 10 : null;

  return (
    <Table.Tr>
      <Table.Td>
        <Text size="xs" component="code">
          {p.test_procedure_id}
        </Text>
      </Table.Td>
      <Table.Td>
        <Group gap={4}>
          {(p.classes ?? []).map((cls) => (
            <Badge key={cls} color="gray" size="xs">
              {cls}
            </Badge>
          ))}
        </Group>
      </Table.Td>
      <Table.Td>
        <Text fw={700}>{p.total_runs}</Text>
      </Table.Td>
      <Table.Td>
        {passPct !== null ? (
          <Group gap="xs" wrap="nowrap">
            <Progress.Root style={{ flex: 1 }} size={10}>
              <Progress.Section value={passPct} color="green" title={`${p.latest_passed} passing`} />
              <Progress.Section value={100 - passPct} color="red" title={`${p.latest_failed} failing`} />
            </Progress.Root>
            <Text size="xs" c="dimmed">
              {passPct}%
            </Text>
          </Group>
        ) : (
          <Text size="xs" c="dimmed">
            —
          </Text>
        )}
      </Table.Td>
      <Table.Td>
        <Text fw={700} c="green">
          {p.latest_passed}
        </Text>
      </Table.Td>
      <Table.Td>
        <Text fw={700} c="red">
          {p.latest_failed}
        </Text>
      </Table.Td>
    </Table.Tr>
  );
}

export function ProcedureTable({ procedures }: { procedures: ProcedureStat[] }) {
  const [showAll, setShowAll] = useState(false);
  if (procedures.length === 0) return null;
  const displayed = showAll ? procedures : procedures.slice(0, 20);

  return (
    <SectionCard
      title={
        <Group gap="xs">
          <Text fw={700}>Test Procedures</Text>
          <Badge color="gray">{procedures.length}</Badge>
          <Text size="xs" c="dimmed">
            sorted by total runs · pass rate = latest run per group
          </Text>
        </Group>
      }
    >
      <Table.ScrollContainer minWidth={600}>
        <Table striped highlightOnHover fz="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Procedure</Table.Th>
              <Table.Th>Classes</Table.Th>
              <Table.Th>Total Runs</Table.Th>
              <Table.Th>Pass Rate (current)</Table.Th>
              <Table.Th c="green">Passing</Table.Th>
              <Table.Th c="red">Failing</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {displayed.map((p) => (
              <ProcedureRow key={p.test_procedure_id} p={p} />
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
      {!showAll && procedures.length > 20 && (
        <Button variant="default" size="xs" mt="sm" onClick={() => setShowAll(true)}>
          Show all {procedures.length} procedures
        </Button>
      )}
    </SectionCard>
  );
}
