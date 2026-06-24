import { Button, SimpleGrid, Stack } from '@mantine/core';
import { useDocumentTitle } from '@mantine/hooks';
import { IconArrowLeft } from '@tabler/icons-react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { fetchAdminStats } from '../../api/admin';
import { ApiError } from '../../api/client';
import { ErrorAlert } from '../../components/ErrorAlert';
import { PageHeader } from '../../components/PageHeader';
import { PageSpinner } from '../../components/PageSpinner';
import { Overview } from './Overview';
import { ProcedureTable } from './ProcedureTable';
import { SummaryCard } from './SummaryCard';
import { UserLeaderboard } from './UserLeaderboard';
import { WeekBars } from './WeekBars';

export function AdminStatsPage() {
  useDocumentTitle('Platform Stats - CACTUS');
  const { data, isPending, error } = useQuery({
    queryKey: ['admin', 'stats'],
    queryFn: fetchAdminStats,
  });

  if (isPending) return <PageSpinner />;
  if (error instanceof ApiError && error.status === 403) return <ErrorAlert message="Access denied." />;
  if (error) return <ErrorAlert message="Failed to retrieve stats." />;

  const avgRunsPerUser =
    data.total_users > 0 ? Math.round((data.total_runs / data.total_users) * 10) / 10 : null;

  return (
    <Stack gap="md">
      <PageHeader title="Platform Stats">
        <Button
          component={Link}
          to="/admin"
          variant="default"
          size="xs"
          leftSection={<IconArrowLeft size={14} />}
        >
          Back to Admin
        </Button>
      </PageHeader>

      <SimpleGrid cols={{ base: 1, xs: 2, sm: 4 }}>
        <SummaryCard
          value={data.max_run_number}
          label="Total Runs"
          sub={`incl. ${data.max_run_number - data.total_runs} deleted`}
        />
        <SummaryCard value={data.total_users} label="Total Users" />
        <SummaryCard value={data.total_run_groups} label="Run Groups" />
        <SummaryCard value={avgRunsPerUser ?? '—'} label="Avg Runs per User" />
      </SimpleGrid>

      <Overview
        versionCounts={data.version_counts}
        totalPassed={data.total_passed}
        totalFailed={data.total_failed}
      />
      <WeekBars bars={data.runs_per_week} />
      <ProcedureTable procedures={data.procedures} />
      <UserLeaderboard entries={data.user_leaderboard} />
    </Stack>
  );
}
