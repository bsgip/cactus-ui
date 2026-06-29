import { Button, Flex, Grid } from '@radix-ui/themes';
import {
  IconArrowLeft,
  IconPlayerPlayFilled,
  IconStack2,
  IconUserBolt,
  IconUsers,
} from '@tabler/icons-react';
import { useQuery } from '@tanstack/react-query';
import { Link as RouterLink } from 'react-router-dom';
import { fetchAdminStats } from '../../api/admin';
import { ApiError } from '../../api/client';
import { ErrorAlert } from '../../components/ErrorAlert';
import { PageHeader } from '../../components/PageHeader';
import { PageSpinner } from '../../components/PageSpinner';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
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
    <Flex direction="column" gap="3">
      <PageHeader title="Platform Stats">
        <Button asChild variant="soft" color="gray" size="1">
          <RouterLink to="/admin">
            <IconArrowLeft size={14} />
            Back to Admin
          </RouterLink>
        </Button>
      </PageHeader>

      <Grid columns={{ initial: '1', xs: '2', sm: '4' }} gap="3">
        <SummaryCard
          value={data.max_run_number}
          label="Total Runs"
          sub={`incl. ${data.max_run_number - data.total_runs} deleted`}
          icon={<IconPlayerPlayFilled size={22} />}
          accent="green"
        />
        <SummaryCard
          value={data.total_users}
          label="Total Users"
          icon={<IconUsers size={22} />}
          accent="blue"
        />
        <SummaryCard
          value={data.total_run_groups}
          label="Run Groups"
          icon={<IconStack2 size={22} />}
          accent="cyan"
        />
        <SummaryCard
          value={avgRunsPerUser ?? '—'}
          label="Avg Runs per User"
          icon={<IconUserBolt size={22} />}
          accent="amber"
        />
      </Grid>

      <Overview
        versionCounts={data.version_counts}
        totalPassed={data.total_passed}
        totalFailed={data.total_failed}
      />
      <WeekBars bars={data.runs_per_week} />
      <ProcedureTable procedures={data.procedures} />
      <UserLeaderboard entries={data.user_leaderboard} />
    </Flex>
  );
}
