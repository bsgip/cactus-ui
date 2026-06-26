import { Badge, Box, Button, DropdownMenu, Flex, Heading, Link, Separator, Table, Text } from '@radix-ui/themes';
import { IconChevronDown } from '@tabler/icons-react';
import { useQuery } from '@tanstack/react-query';
import { Link as RouterLink, useNavigate, useParams } from 'react-router-dom';
import { fetchCompliance } from '../api/runGroup';
import { fetchRunGroups } from '../api/runs';
import type { ComplianceStatus } from '../api/types';
import { Banner } from '../components/Banner';
import { ErrorAlert } from '../components/ErrorAlert';
import { PageSpinner } from '../components/PageSpinner';
import { useDocumentTitle } from '../hooks/useDocumentTitle';
import { useSession } from '../hooks/useSession';

const STATUS_COLOR: Record<ComplianceStatus, 'green' | 'red' | 'blue' | 'gray'> = {
  success: 'green',
  failed: 'red',
  active: 'blue',
  runless: 'gray',
  unknown: 'gray',
};

export function RunGroupPage({ isAdminView }: { isAdminView: boolean }) {
  useDocumentTitle('Compliance - CACTUS');
  const { runGroupId: runGroupIdParam } = useParams();
  const runGroupId = Number(runGroupIdParam);
  const navigate = useNavigate();
  const { data: session } = useSession();

  const groupsQuery = useQuery({
    queryKey: ['run_groups', isAdminView ? runGroupId : 'mine'],
    queryFn: () => fetchRunGroups(isAdminView, runGroupId),
  });

  const complianceQuery = useQuery({
    queryKey: ['compliance', runGroupId, isAdminView],
    queryFn: () => fetchCompliance(runGroupId, isAdminView),
  });

  const runGroups = groupsQuery.data?.items ?? [];
  const activeRunGroup = runGroups.find((rg) => rg.run_group_id === runGroupId);
  const groupPath = (id: number) => `${isAdminView ? '/admin' : ''}/group/${id}`;
  const groupRunsPath = (id: number) => `${isAdminView ? '/admin' : ''}/group/${id}/runs`;

  if (groupsQuery.isPending || complianceQuery.isPending) {
    return <PageSpinner />;
  }

  return (
    <>
      <Banner message={session?.banner_message} />
      {groupsQuery.error && <ErrorAlert message="Unable to fetch run groups." />}
      {complianceQuery.error && <ErrorAlert message="Unable to fetch compliance data." />}

      <Flex justify="between" align="center" mb="1">
        <Flex gap="2" align="center">
          <Heading as="h2" size="6">
            Compliance for
          </Heading>
          {runGroups.length < 2 ? (
            activeRunGroup && (
              <Heading as="h2" size="6">
                {activeRunGroup.name}
              </Heading>
            )
          ) : (
            <DropdownMenu.Root>
              <DropdownMenu.Trigger>
                <Button>
                  {activeRunGroup?.name}
                  <IconChevronDown size={16} />
                </Button>
              </DropdownMenu.Trigger>
              <DropdownMenu.Content>
                {runGroups
                  .filter((rg) => rg.run_group_id !== runGroupId)
                  .map((rg) => (
                    <DropdownMenu.Item
                      key={rg.run_group_id}
                      onSelect={() => navigate(groupPath(rg.run_group_id))}
                    >
                      {rg.name}
                    </DropdownMenu.Item>
                  ))}
              </DropdownMenu.Content>
            </DropdownMenu.Root>
          )}
        </Flex>
        {activeRunGroup && (
          <Link asChild>
            <RouterLink to={groupRunsPath(runGroupId)}>
              All runs for <b>{activeRunGroup.name}</b> →
            </RouterLink>
          </Link>
        )}
      </Flex>

      <Separator size="4" mb="3" />

      {isAdminView && (
        <Flex justify="end" mb="3">
          <Button asChild>
            <a href={`/admin/group/${runGroupId}/compliance_pdf`}>Generate Compliance Report</a>
          </Button>
        </Flex>
      )}

      {complianceQuery.data && complianceQuery.data.compliance_by_class.length === 0 && (
        <Text color="gray">No compliance classes found for this run group.</Text>
      )}

      {complianceQuery.data && complianceQuery.data.compliance_by_class.length > 0 && (
        <>
          <Box style={{ overflow: 'auto' }}>
            <Table.Root variant="surface">
              <Table.Header>
                <Table.Row>
                  <Table.ColumnHeaderCell />
                  <Table.ColumnHeaderCell>Class</Table.ColumnHeaderCell>
                  <Table.ColumnHeaderCell />
                  <Table.ColumnHeaderCell>Latest Runs</Table.ColumnHeaderCell>
                </Table.Row>
              </Table.Header>
              <Table.Body>
                {complianceQuery.data.compliance_by_class.map((entry) => (
                  <Table.Row key={entry.class_name}>
                    <Table.Cell
                      style={
                        entry.compliant ? { backgroundColor: 'var(--green-9)' } : undefined
                      }
                    />
                    <Table.Cell style={{ fontWeight: 'bold', whiteSpace: 'nowrap' }}>
                      {entry.class_name}
                    </Table.Cell>
                    <Table.Cell>{entry.class_details.description}</Table.Cell>
                    <Table.Cell>
                      {entry.per_run_status.map((rs) => {
                        const color = STATUS_COLOR[rs.status];
                        const hasLink =
                          rs.latest_run_id !== null &&
                          (rs.status === 'active' ||
                            rs.status === 'success' ||
                            rs.status === 'failed');
                        if (hasLink) {
                          return (
                            <Badge key={rs.test_procedure_id} asChild color={color} mr="2" mb="2">
                              <RouterLink
                                to={`${isAdminView ? '/admin' : ''}/run/${rs.latest_run_id}`}
                                style={{ cursor: 'pointer' }}
                              >
                                {rs.test_procedure_id} ({rs.latest_run_id})
                              </RouterLink>
                            </Badge>
                          );
                        }
                        return (
                          <Badge key={rs.test_procedure_id} color={color} mr="2" mb="2">
                            {rs.test_procedure_id}
                          </Badge>
                        );
                      })}
                    </Table.Cell>
                  </Table.Row>
                ))}
              </Table.Body>
            </Table.Root>
          </Box>

          <Text as="div" mt="2" size="2">
            This compliance table shows whether the criteria for each compliance class has been met.
            Each test procedure required by a compliance class is shown next to the compliance class.
            The test procedures are colour-coded by the success of the <i>most recent run</i>, for
            example <Badge color="green">Passed</Badge> or <Badge color="red">Failed</Badge>.{' '}
            <Badge color="blue">Active</Badge> indicates the test procedure is currently in progress
            and <Badge color="gray">No Runs</Badge> indicates test procedures that have never been
            run.
          </Text>
        </>
      )}
    </>
  );
}
