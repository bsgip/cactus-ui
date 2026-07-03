import { Badge, Box, Button, Code, Flex, Table, Text } from '@radix-ui/themes';
import { IconMicroscope } from '@tabler/icons-react';
import { useState } from 'react';
import type { ProcedureStat } from '../../api/types';
import { SectionCard } from '../../components/SectionCard';

function ProcedureRow({ p }: { p: ProcedureStat }) {
  const assessed = p.latest_passed + p.latest_failed;
  const passPct = assessed > 0 ? Math.round((p.latest_passed / assessed) * 1000) / 10 : null;

  return (
    <Table.Row>
      <Table.Cell>
        <Code size="1">{p.test_procedure_id}</Code>
      </Table.Cell>
      <Table.Cell>
        <Flex gap="1" wrap="wrap">
          {(p.classes ?? []).map((cls) => (
            <Badge key={cls} color="gray" size="1">
              {cls}
            </Badge>
          ))}
        </Flex>
      </Table.Cell>
      <Table.Cell>
        <Text weight="bold">{p.total_runs}</Text>
      </Table.Cell>
      <Table.Cell>
        {passPct !== null ? (
          <Flex gap="2" align="center">
            <Flex
              style={{ flex: 1, height: 10, borderRadius: 'var(--radius-1)', overflow: 'hidden' }}
            >
              <div
                title={`${p.latest_passed} passing`}
                style={{ width: `${passPct}%`, backgroundColor: 'var(--green-9)' }}
              />
              <div
                title={`${p.latest_failed} failing`}
                style={{ width: `${100 - passPct}%`, backgroundColor: 'var(--red-9)' }}
              />
            </Flex>
            <Text size="1" color="gray">
              {passPct}%
            </Text>
          </Flex>
        ) : (
          <Text size="1" color="gray">
            —
          </Text>
        )}
      </Table.Cell>
      <Table.Cell>
        <Text weight="bold" color="green">
          {p.latest_passed}
        </Text>
      </Table.Cell>
      <Table.Cell>
        <Text weight="bold" color="red">
          {p.latest_failed}
        </Text>
      </Table.Cell>
    </Table.Row>
  );
}

export function ProcedureTable({ procedures }: { procedures: ProcedureStat[] }) {
  const [showAll, setShowAll] = useState(false);
  if (procedures.length === 0) return null;
  const displayed = showAll ? procedures : procedures.slice(0, 20);

  return (
    <SectionCard
      title={
        <Flex gap="2" align="center">
          <IconMicroscope size={16} />
          <Text weight="bold">Test Procedures</Text>
          <Badge color="gray">{procedures.length}</Badge>
          <Text size="1" color="gray">
            sorted by total runs · pass rate = latest run per group
          </Text>
        </Flex>
      }
    >
      <Box style={{ overflow: 'auto' }}>
        <Table.Root variant="surface" size="1">
          <Table.Header>
            <Table.Row>
              <Table.ColumnHeaderCell>Procedure</Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell>Classes</Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell>Total Runs</Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell>Pass Rate (current)</Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell style={{ color: 'var(--green-11)' }}>
                Passing
              </Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell style={{ color: 'var(--red-11)' }}>
                Failing
              </Table.ColumnHeaderCell>
            </Table.Row>
          </Table.Header>
          <Table.Body>
            {displayed.map((p) => (
              <ProcedureRow key={p.test_procedure_id} p={p} />
            ))}
          </Table.Body>
        </Table.Root>
      </Box>
      {!showAll && procedures.length > 20 && (
        <Button variant="soft" color="gray" size="1" mt="2" onClick={() => setShowAll(true)}>
          Show all {procedures.length} procedures
        </Button>
      )}
    </SectionCard>
  );
}
