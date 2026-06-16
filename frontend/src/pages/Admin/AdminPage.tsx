import { Anchor, Button, Group, Table, Text, TextInput, Title } from '@mantine/core';
import { useDocumentTitle } from '@mantine/hooks';
import { useQuery } from '@tanstack/react-query';
import { useMemo, useState } from 'react';
import { fetchAdminUsers } from '../../api/admin';
import { ApiError } from '../../api/client';
import type { AdminUserResponse } from '../../api/types';
import { ErrorAlert } from '../../components/ErrorAlert';
import { PageSpinner } from '../../components/PageSpinner';

function UserRow({ user }: { user: AdminUserResponse }) {
  return (
    <Table.Tr>
      <Table.Td>{user.user_id}</Table.Td>
      <Table.Td>{user.name ? <strong>{user.name}</strong> : '-'}</Table.Td>
      <Table.Td>
        {user.run_groups.length === 0 ? (
          'No run groups found.'
        ) : (
          user.run_groups.map((rg) => (
            <Anchor
              key={rg.run_group_id}
              href={`/admin/group/${rg.run_group_id}/runs`}
              mr="sm"
            >
              {rg.name} ({rg.run_group_id})
            </Anchor>
          ))
        )}
      </Table.Td>
    </Table.Tr>
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
      <Group justify="space-between" align="center" mb="xs">
        <Title order={2}>Admin</Title>
        <Button component="a" href="/admin/stats" variant="outline" color="green" size="xs">
          Platform Stats
        </Button>
      </Group>

      <TextInput
        placeholder="Search by user name, run group name or by user/run groups IDs"
        aria-label="Search"
        value={filter}
        onChange={(e) => setFilter(e.currentTarget.value)}
        mb="sm"
      />

      <Table.ScrollContainer minWidth={400} style={{ flex: 1 }}>
        <Table striped>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>User ID</Table.Th>
              <Table.Th>User Name</Table.Th>
              <Table.Th>Run Groups</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {filteredUsers.length === 0 ? (
              <Table.Tr>
                <Table.Td colSpan={3} style={{ textAlign: 'center' }}>
                  <Text c="dimmed">No users found.</Text>
                </Table.Td>
              </Table.Tr>
            ) : (
              filteredUsers.map((user) => <UserRow key={user.user_id} user={user} />)
            )}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
    </div>
  );
}
