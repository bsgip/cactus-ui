import { TextField } from '@radix-ui/themes';
import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { fetchAdminUsers } from '../api/admin';
import { ApiError } from '../api/client';
import { ErrorAlert } from '../components/ErrorAlert';
import { PageSpinner } from '../components/PageSpinner';
import { useDocumentTitle } from '../hooks/useDocumentTitle';
import Page from '../components/Page';
import UserTable from '../components/UserTable';


export function AdminPage() {
  useDocumentTitle('Admin - CACTUS');
  const [filter, setFilter] = useState('');

  const query = useQuery({
    queryKey: ['admin', 'users'],
    queryFn: fetchAdminUsers,
  });

  const filteredUsers = useMemo(() => {
    if (!query.data) return [];
    if (!filter) return query.data.users;
    try {
      const re = new RegExp(filter);
      return query.data.users.filter((u) => re.test(u.matchable_description));
    } catch {
      return query.data.users.filter((u) => u.matchable_description.includes(filter));
    }
  }, [query.data, filter]);

  return (
    <Page title="Admin">

      <TextField.Root
        placeholder="Search by user name, run group name or by user/run groups IDs"
        value={filter}
        onChange={(e) => setFilter(e.currentTarget.value)}
        mb="4"
      />

      {query.isPending ? (
        <PageSpinner />
      ) : (query.error instanceof ApiError && query.error.status === 403) ? (
        <ErrorAlert message="Access denied." />
      ) : query.error ? (
        <ErrorAlert message="Unable to fetch users." />
      ) : (
        <UserTable filteredUsers={filteredUsers} />
      )}

    </Page>
  );
}
