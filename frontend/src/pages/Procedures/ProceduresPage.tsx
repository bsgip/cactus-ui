import { Anchor, Table, Title } from '@mantine/core';
import { useDocumentTitle } from '@mantine/hooks';
import { useQuery } from '@tanstack/react-query';
import { fetchProcedures } from '../../api/procedures';
import { Banner } from '../../components/Banner';
import { ErrorAlert } from '../../components/ErrorAlert';
import { PageSpinner } from '../../components/PageSpinner';
import { useSession } from '../../hooks/useSession';

// Port of procedures.html.
export function ProceduresPage() {
  useDocumentTitle('Procedures - CACTUS');
  const { data: session } = useSession();
  const { data, isPending, error } = useQuery({
    queryKey: ['procedures'],
    queryFn: fetchProcedures,
  });

  return (
    <>
      <Banner message={session?.banner_message} />
      <Title order={2} mb="md">
        Test Procedures
      </Title>

      {isPending ? (
        <PageSpinner />
      ) : error ? (
        <ErrorAlert message="Failed to retrieve procedures." />
      ) : (
        <Table striped>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Test Procedure ID</Table.Th>
              <Table.Th>Description</Table.Th>
              <Table.Th>Category</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {data.procedures.length === 0 ? (
              <Table.Tr>
                <Table.Td colSpan={3} ta="center">
                  No procedures available.
                </Table.Td>
              </Table.Tr>
            ) : (
              data.procedures.map((procedure) => (
                <Table.Tr key={procedure.test_procedure_id}>
                  <Table.Td>
                    {/* /procedure/<id> is still Flask-rendered (page 2): plain anchor, not <Link> */}
                    <Anchor href={`/procedure/${procedure.test_procedure_id}`}>
                      {procedure.test_procedure_id}
                    </Anchor>
                  </Table.Td>
                  <Table.Td>{procedure.description}</Table.Td>
                  <Table.Td>{procedure.category}</Table.Td>
                </Table.Tr>
              ))
            )}
          </Table.Tbody>
        </Table>
      )}
    </>
  );
}
