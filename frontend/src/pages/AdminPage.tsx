import { Box, Button, Flex, Heading, Link, Table, Text, TextField } from '@radix-ui/themes';
import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { fetchAdminUsers } from '../api/admin';
import { ApiError } from '../api/client';
import type { AdminUserResponse } from '../api/types';
import { ErrorAlert } from '../components/ErrorAlert';
import { PageSpinner } from '../components/PageSpinner';
import { useDocumentTitle } from '../hooks/useDocumentTitle';

function UserRow({ user }: { user: AdminUserResponse }) {
  return (
    <Table.Row>
      <Table.Cell>{user.user_id}</Table.Cell>
      <Table.Cell>{user.name ? <strong>{user.name}</strong> : '-'}</Table.Cell>
      <Table.Cell>
        {user.run_groups.length === 0
          ? 'No run groups found.'
          : user.run_groups.map((rg) => (
              <Link key={rg.run_group_id} href={`/admin/group/${rg.run_group_id}/runs`} mr="2">
                {rg.name} ({rg.run_group_id})
              </Link>
            ))}
      </Table.Cell>
    </Table.Row>
  );
}

export function AdminPage() {
  useDocumentTitle('Admin - CACTUS');
  const [filter, setFilter] = useState('');

  const { data, isPending, error } = useQuery({
    queryKey: ['admin', 'users'],
    queryFn: fetchAdminUsers,
  });

  const filteredUsers = useMemo(() => {
    if (!data) return [];
    if (!filter) return data.users;
    try {
      const re = new RegExp(filter);
      return data.users.filter((u) => re.test(u.matchable_description));
    } catch {
      return data.users.filter((u) => u.matchable_description.includes(filter));
    }
  }, [data, filter]);

  if (isPending) return <PageSpinner />;

  if (error instanceof ApiError && error.status === 403) {
    return <ErrorAlert message="Access denied." />;
  }

  if (error) {
    return <ErrorAlert message="Unable to fetch users." />;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <Flex justify="between" align="center" mb="1">
        <Heading as="h2" size="6">
          Admin
        </Heading>
        <Button asChild variant="outline" color="green" size="1">
          <a href="/admin/stats">Platform Stats</a>
        </Button>
      </Flex>

      <TextField.Root
        placeholder="Search by user name, run group name or by user/run groups IDs"
        aria-label="Search"
        value={filter}
        onChange={(e) => setFilter(e.currentTarget.value)}
        mb="2"
      />

      <Box style={{ flex: 1, overflow: 'auto' }}>
        <Table.Root variant="surface">
          <Table.Header>
            <Table.Row>
              <Table.ColumnHeaderCell>User ID</Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell>User Name</Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell>Run Groups</Table.ColumnHeaderCell>
            </Table.Row>
          </Table.Header>
          <Table.Body>
            {filteredUsers.length === 0 ? (
              <Table.Row>
                <Table.Cell colSpan={3} style={{ textAlign: 'center' }}>
                  <Text color="gray">No users found.</Text>
                </Table.Cell>
              </Table.Row>
            ) : (
              filteredUsers.map((user) => <UserRow key={user.user_id} user={user} />)
            )}
          </Table.Body>
        </Table.Root>
      </Box>
    </div>
  );
}
