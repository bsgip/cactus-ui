import { Box, Table, Text } from '@radix-ui/themes';
import type { AdminUserResponse } from '../api/types';
import UserRow from './UserRow';

function UserTable({filteredUsers}:{filteredUsers: AdminUserResponse[]}) {
  return (
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
  );
}

export default UserTable;
