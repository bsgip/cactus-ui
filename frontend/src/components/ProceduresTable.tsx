import { Flex, Link, Table } from '@radix-ui/themes';
import { Link as RouterLink } from 'react-router-dom';

import type { ProceduresResponse } from '../api/generated/types';
import { InfoPopover } from '../components/InfoPopover';

function ProceduresTable({data}: {data: ProceduresResponse}) {
  return (
         <Table.Root variant="surface">
          <Table.Header>
            <Table.Row>
              <Table.ColumnHeaderCell>Test Procedure ID</Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell>Description</Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell>Category</Table.ColumnHeaderCell>
            </Table.Row>
          </Table.Header>
          <Table.Body>
            {data.procedures.length === 0 ? (
              <Table.Row>
                <Table.Cell colSpan={3} style={{ textAlign: 'center' }}>
                  No procedures available.
                </Table.Cell>
              </Table.Row>
            ) : (
              data.procedures.map((procedure) => (
                <Table.Row key={procedure.test_procedure_id}>
                  <Table.Cell>
                    <Link asChild>
                      <RouterLink to={`/procedure/${procedure.test_procedure_id}`}>
                        {procedure.test_procedure_id}
                      </RouterLink>
                    </Link>
                  </Table.Cell>
                  <Table.Cell>{procedure.description}</Table.Cell>
                  <Table.Cell>
                    {procedure.category.toLowerCase() === 'provisional' ? (
                      <Flex gap="1" align="center">
                        <span>{procedure.category}</span>
                        <InfoPopover title="Provisional tests" label="What are provisional tests?">
                          Provisional tests aren&apos;t required for CSIP-Aus compliance.
                          They&apos;re drawn from real-world integration issues seen in the field,
                          and we strongly recommend running them to catch problems before
                          deployment.
                        </InfoPopover>
                      </Flex>
                    ) : (
                      procedure.category
                    )}
                  </Table.Cell>
                </Table.Row>
              ))
            )}
          </Table.Body>
        </Table.Root>
)
};

export default ProceduresTable;
