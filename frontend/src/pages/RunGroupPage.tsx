import {
  Anchor,
  Badge,
  Box,
  Button,
  Divider,
  Group,
  Menu,
  Table,
  Text,
  Title,
} from '@mantine/core';
import { useDocumentTitle } from '@mantine/hooks';
import { IconChevronDown } from '@tabler/icons-react';
import { useQuery } from '@tanstack/react-query';
import { Link, useParams } from 'react-router-dom';
import { fetchCompliance } from '../api/runGroup';
import { fetchRunGroups } from '../api/runs';
import type { ComplianceStatus } from '../api/types';
import { Banner } from '../components/Banner';
import { ErrorAlert } from '../components/ErrorAlert';
import { PageSpinner } from '../components/PageSpinner';
import { useSession } from '../hooks/useSession';

const STATUS_COLOR: Record<ComplianceStatus, string> = {
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

      <Group justify="space-between" mb="xs">
        <Group gap="sm">
          <Title order={2}>Compliance for</Title>
          {runGroups.length < 2 ? (
            activeRunGroup && <Title order={2}>{activeRunGroup.name}</Title>
          ) : (
            <Menu>
              <Menu.Target>
                <Button rightSection={<IconChevronDown size={16} />}>
                  {activeRunGroup?.name}
                </Button>
              </Menu.Target>
              <Menu.Dropdown>
                {runGroups
                  .filter((rg) => rg.run_group_id !== runGroupId)
                  .map((rg) => (
                    <Menu.Item key={rg.run_group_id} component={Link} to={groupPath(rg.run_group_id)}>
                      {rg.name}
                    </Menu.Item>
                  ))}
              </Menu.Dropdown>
            </Menu>
          )}
        </Group>
        {activeRunGroup && (
          <Anchor component={Link} to={groupRunsPath(runGroupId)} style={{ alignContent: 'center' }}>
            All runs for <b>{activeRunGroup.name}</b> →
          </Anchor>
        )}
      </Group>

      <Divider mb="md" />

      {isAdminView && (
        <Group justify="flex-end" mb="md">
          <Button component="a" href={`/admin/group/${runGroupId}/compliance_pdf`}>
            Generate Compliance Report
          </Button>
        </Group>
      )}

      {complianceQuery.data && complianceQuery.data.compliance_by_class.length === 0 && (
        <Text c="dimmed">No compliance classes found for this run group.</Text>
      )}

      {complianceQuery.data && complianceQuery.data.compliance_by_class.length > 0 && (
        <>
          <Box style={{ overflow: 'auto' }}>
            <Table striped>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th />
                  <Table.Th>Class</Table.Th>
                  <Table.Th />
                  <Table.Th>Latest Runs</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {complianceQuery.data.compliance_by_class.map((entry) => (
                  <Table.Tr key={entry.class_name}>
                    <Table.Th
                      style={
                        entry.compliant
                          ? { backgroundColor: 'var(--mantine-color-green-6)' }
                          : undefined
                      }
                    />
                    <Table.Td fw="bold" style={{ whiteSpace: 'nowrap' }}>
                      {entry.class_name}
                    </Table.Td>
                    <Table.Td>{entry.class_details.description}</Table.Td>
                    <Table.Td>
                      {entry.per_run_status.map((rs) => {
                        const color = STATUS_COLOR[rs.status];
                        const hasLink =
                          rs.latest_run_id !== null &&
                          (rs.status === 'active' ||
                            rs.status === 'success' ||
                            rs.status === 'failed');
                        if (hasLink) {
                          return (
                            <Badge
                              key={rs.test_procedure_id}
                              color={color}
                              component={Link}
                              to={`${isAdminView ? '/admin' : ''}/run/${rs.latest_run_id}`}
                              style={{ cursor: 'pointer' }}
                              mr={6}
                              mb={8}
                            >
                              {rs.test_procedure_id} ({rs.latest_run_id})
                            </Badge>
                          );
                        }
                        return (
                          <Badge key={rs.test_procedure_id} color={color} mr={6} mb={8}>
                            {rs.test_procedure_id}
                          </Badge>
                        );
                      })}
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Box>

          <Text component="div" mt="sm" size="sm">
            This compliance table shows whether the criteria for each compliance class has been met.
            Each test procedure required by a compliance class is shown next to the compliance class.
            The test procedures are colour-coded by the success of the <i>most recent run</i>, for
            example <Badge color="green">Passed</Badge> or{' '}
            <Badge color="red">Failed</Badge>.{' '}
            <Badge color="blue">Active</Badge> indicates the test procedure is currently in progress
            and <Badge color="gray">No Runs</Badge> indicates test procedures that have never been
            run.
          </Text>
        </>
      )}
    </>
  );
}
