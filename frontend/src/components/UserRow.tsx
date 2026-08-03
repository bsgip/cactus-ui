import { Link, Table } from '@radix-ui/themes';
import type { AdminUserResponse } from '../api/types';

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

export default UserRow;
