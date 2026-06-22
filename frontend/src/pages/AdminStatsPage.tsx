import {
  Badge,
  Box,
  Button,
  Grid,
  Group,
  Paper,
  Progress,
  SimpleGrid,
  Table,
  Text,
  Title,
} from '@mantine/core';
import { useDocumentTitle } from '@mantine/hooks';
import { IconArrowLeft } from '@tabler/icons-react';
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { fetchAdminStats } from '../api/admin';
import { ApiError } from '../api/client';
import type { ProcedureStat, UserLeaderboardEntry, WeekBar } from '../api/types';
import { ErrorAlert } from '../components/ErrorAlert';
import { PageSpinner } from '../components/PageSpinner';

function SummaryCard({
  value,
  label,
  sub,
  color,
}: {
  value: string | number;
  label: string;
  sub?: string;
  color: string;
}) {
  return (
    <Paper shadow="sm" p="md" style={{ borderLeft: `4px solid var(--mantine-color-${color}-6)` }}>
      <Box ta="center">
        <Text fz="2rem" fw={700}>
          {value}
        </Text>
        <Text size="sm" c="dimmed">
          {label}
        </Text>
        <Text fz="0.7rem" c="dimmed" style={{ minHeight: '1rem' }}>
          {sub ?? ' '}
        </Text>
      </Box>
    </Paper>
  );
}

function WeekBars({ bars }: { bars: WeekBar[] }) {
  if (bars.length === 0) return null;
  const maxCount = Math.max(...bars.map((b) => b.count), 1);

  return (
    <Paper shadow="sm" mb="md">
      <Box p="xs" style={{ borderBottom: '1px solid var(--mantine-color-gray-3)' }}>
        <Text fw={700} size="sm">
          Tests Per Week
        </Text>
      </Box>
      <Box p="sm">
        <Box style={{ display: 'flex', alignItems: 'flex-end', gap: 2, height: 110 }}>
          {bars.map((bar, i) => {
            const barH = Math.max(2, Math.round((bar.count / maxCount) * 80));
            return (
              <Box
                key={i}
                style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flex: 1, minWidth: 0 }}
              >
                <Text fz="0.6rem" c="dimmed" style={{ lineHeight: 1.2 }}>
                  {bar.count}
                </Text>
                <Box
                  title={`${bar.month || ''} ${bar.year || ''}: ${bar.count} runs`.trim()}
                  style={{
                    width: '100%',
                    height: barH,
                    backgroundColor: 'var(--mantine-color-green-6)',
                    borderRadius: '2px 2px 0 0',
                  }}
                />
              </Box>
            );
          })}
        </Box>
        <Box style={{ display: 'flex', gap: 2, marginTop: 3, borderTop: '1px solid var(--mantine-color-gray-3)' }}>
          {bars.map((bar, i) => (
            <Box key={i} style={{ flex: 1, minWidth: 0, textAlign: 'center' }}>
              <Text
                fz="0.6rem"
                c="dimmed"
                style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'block' }}
              >
                {bar.month || ' '}
              </Text>
              <Text
                fz="0.6rem"
                c="dimmed"
                style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'block' }}
              >
                {bar.year || ' '}
              </Text>
            </Box>
          ))}
        </Box>
      </Box>
    </Paper>
  );
}

function ProcedureRow({ p }: { p: ProcedureStat }) {
  const latestAssessed = p.latest_passed + p.latest_failed;
  const passPct = latestAssessed > 0 ? Math.round((p.latest_passed / latestAssessed) * 100 * 10) / 10 : null;

  return (
    <Table.Tr>
      <Table.Td>
        <Text size="xs" component="code">
          {p.test_procedure_id}
        </Text>
      </Table.Td>
      <Table.Td>
        {(p.classes ?? []).map((cls) => (
          <Badge key={cls} color="gray" size="xs" mr={4} style={{ fontSize: '0.65rem' }}>
            {cls}
          </Badge>
        ))}
      </Table.Td>
      <Table.Td>
        <Text fw={700}>{p.total_runs}</Text>
      </Table.Td>
      <Table.Td style={{ minWidth: 180 }}>
        {passPct !== null ? (
          <Group gap="xs" wrap="nowrap">
            <Progress.Root style={{ flex: 1 }} size={10}>
              <Progress.Section
                value={passPct}
                color="green"
                title={`${p.latest_passed} passing`}
              />
              <Progress.Section
                value={100 - passPct}
                color="red"
                title={`${p.latest_failed} failing`}
              />
            </Progress.Root>
            <Text size="xs" c="dimmed" style={{ whiteSpace: 'nowrap' }}>
              {passPct}%
            </Text>
          </Group>
        ) : (
          <Text size="xs" c="dimmed">
            —
          </Text>
        )}
      </Table.Td>
      <Table.Td>
        <Text fw={700} c="green">
          {p.latest_passed}
        </Text>
      </Table.Td>
      <Table.Td>
        <Text fw={700} c="red">
          {p.latest_failed}
        </Text>
      </Table.Td>
    </Table.Tr>
  );
}

function UserLeaderboardRow({
  entry,
  rank,
  maxRunCount,
}: {
  entry: UserLeaderboardEntry;
  rank: number;
  maxRunCount: number;
}) {
  const pct = maxRunCount > 0 ? Math.round((entry.run_count / maxRunCount) * 100 * 10) / 10 : 0;
  return (
    <Box style={{ display: 'flex', alignItems: 'center', marginBottom: 4, height: 28 }}>
      <Text c="dimmed" size="sm" style={{ minWidth: 24, textAlign: 'right', marginRight: 8 }}>
        {rank}
      </Text>
      <Text
        size="sm"
        style={{ width: 180, flexShrink: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginRight: 8 }}
      >
        {entry.name}
      </Text>
      <Box style={{ flex: 1, marginRight: 8 }}>
        <Progress value={pct} color="green" size={16} />
      </Box>
      <Text fw={700} size="sm" style={{ minWidth: 36, textAlign: 'right' }}>
        {entry.run_count}
      </Text>
    </Box>
  );
}

export function AdminStatsPage() {
  useDocumentTitle('Platform Stats - CACTUS');
  const [showAllProcedures, setShowAllProcedures] = useState(false);
  const [showAllUsers, setShowAllUsers] = useState(false);

  const { data, isPending, error } = useQuery({
    queryKey: ['admin', 'stats'],
    queryFn: fetchAdminStats,
  });

  if (isPending) return <PageSpinner />;

  if (error instanceof ApiError && error.status === 403) {
    return <ErrorAlert message="Access denied." />;
  }

  if (error) {
    return <ErrorAlert message="Failed to retrieve stats." />;
  }

  const totalAssessed = data.total_passed + data.total_failed;
  const passRate = totalAssessed > 0 ? Math.round((data.total_passed / totalAssessed) * 100 * 10) / 10 : null;
  const avgRunsPerUser =
    data.total_users > 0 ? Math.round((data.total_runs / data.total_users) * 10) / 10 : null;
  const maxUserRuns = data.user_leaderboard.length > 0 ? data.user_leaderboard[0].run_count : 1;

  const displayedProcedures = showAllProcedures ? data.procedures : data.procedures.slice(0, 20);
  const displayedUsers = showAllUsers ? data.user_leaderboard : data.user_leaderboard.slice(0, 20);

  const sortedVersions = Object.entries(data.version_counts).sort(([a], [b]) => a.localeCompare(b));

  return (
    <Box pt="xs">
      <Group justify="space-between" align="center" mb="md">
        <Title order={2}>Platform Stats</Title>
        <Button
          component={Link}
          to="/admin"
          variant="outline"
          color="gray"
          size="xs"
          leftSection={<IconArrowLeft size={14} />}
        >
          Back to Admin
        </Button>
      </Group>

      <SimpleGrid cols={{ base: 1, xs: 2, sm: 4 }} mb="md">
        <SummaryCard
          value={data.max_run_number}
          label="Total Runs"
          sub={`incl. ${data.max_run_number - data.total_runs} deleted`}
          color="green"
        />
        <SummaryCard value={data.total_users} label="Total Users" color="blue" />
        <SummaryCard value={data.total_run_groups} label="Run Groups" color="cyan" />
        <SummaryCard
          value={avgRunsPerUser !== null ? avgRunsPerUser : '—'}
          label="Avg Runs per User"
          color="yellow"
        />
      </SimpleGrid>

      <Grid mb="md">
        <Grid.Col span={{ base: 12, sm: 4 }}>
          <Paper shadow="sm" h="100%">
            <Box p="xs" style={{ borderBottom: '1px solid var(--mantine-color-gray-3)' }}>
              <Text fw={700} size="sm">
                CSIP-AUS Versions
              </Text>
            </Box>
            {sortedVersions.map(([version, count]) => (
              <Box
                key={version}
                p="xs"
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  borderBottom: '1px solid var(--mantine-color-gray-2)',
                }}
              >
                <Text component="code" size="sm">
                  {version}
                </Text>
                <Badge color="green">
                  {count} run group{count !== 1 ? 's' : ''}
                </Badge>
              </Box>
            ))}
          </Paper>
        </Grid.Col>

        <Grid.Col span={{ base: 12, sm: 8 }}>
          <Paper shadow="sm" h="100%">
            <Box p="xs" style={{ borderBottom: '1px solid var(--mantine-color-gray-3)' }}>
              <Text fw={700} size="sm">
                Current Compliance (latest run per procedure per group)
              </Text>
            </Box>
            <Box p="md">
              <SimpleGrid cols={2} mb="md">
                <Box ta="center">
                  <Text fz="1.75rem" fw={700} c="green">
                    {data.total_passed}
                  </Text>
                  <Text size="sm" c="dimmed">
                    Currently Passing
                  </Text>
                </Box>
                <Box ta="center">
                  <Text fz="1.75rem" fw={700} c="red">
                    {data.total_failed}
                  </Text>
                  <Text size="sm" c="dimmed">
                    Currently Failing
                  </Text>
                </Box>
              </SimpleGrid>
              {passRate !== null && (
                <>
                  <Group justify="space-between" mb={4}>
                    <Text size="sm">Pass rate</Text>
                    <Text size="sm" fw={700}>
                      {passRate}%
                    </Text>
                  </Group>
                  <Progress.Root size={24}>
                    <Progress.Section value={passRate} color="green">
                      <Progress.Label>{data.total_passed} passing</Progress.Label>
                    </Progress.Section>
                    <Progress.Section value={100 - passRate} color="red">
                      <Progress.Label>{data.total_failed} failing</Progress.Label>
                    </Progress.Section>
                  </Progress.Root>
                </>
              )}
            </Box>
          </Paper>
        </Grid.Col>
      </Grid>

      <WeekBars bars={data.runs_per_week} />

      {data.procedures.length > 0 && (
        <Paper shadow="sm" mb="md">
          <Box p="xs" style={{ borderBottom: '1px solid var(--mantine-color-gray-3)' }}>
            <Group gap="xs">
              <Text fw={700} size="sm">
                Test Procedures
              </Text>
              <Badge color="gray" size="sm">
                {data.procedures.length}
              </Badge>
              <Text size="xs" c="dimmed">
                sorted by total runs · pass rate = latest run per group
              </Text>
            </Group>
          </Box>
          <Table.ScrollContainer minWidth={600}>
            <Table striped highlightOnHover fz="sm">
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Procedure</Table.Th>
                  <Table.Th>Classes</Table.Th>
                  <Table.Th title="Total individual runs across all time">Total Runs</Table.Th>
                  <Table.Th
                    title="Current compliance state based on latest run per procedure per run group"
                    style={{ minWidth: 180 }}
                  >
                    Pass Rate (current)
                  </Table.Th>
                  <Table.Th c="green" title="Run groups currently passing this procedure">
                    Passing
                  </Table.Th>
                  <Table.Th c="red" title="Run groups currently failing this procedure">
                    Failing
                  </Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {displayedProcedures.map((p) => (
                  <ProcedureRow key={p.test_procedure_id} p={p} />
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
          {!showAllProcedures && data.procedures.length > 20 && (
            <Box p="sm">
              <Button
                variant="outline"
                color="gray"
                size="xs"
                onClick={() => setShowAllProcedures(true)}
              >
                Show all {data.procedures.length} procedures
              </Button>
            </Box>
          )}
        </Paper>
      )}

      <Paper shadow="sm" mb="md">
        <Box p="xs" style={{ borderBottom: '1px solid var(--mantine-color-gray-3)' }}>
          <Text fw={700} size="sm">
            Runs Per User
          </Text>
        </Box>
        <Box p="sm">
          {data.user_leaderboard.length === 0 ? (
            <Text c="dimmed" size="sm">
              No data yet.
            </Text>
          ) : (
            <>
              {displayedUsers.map((entry, i) => (
                <UserLeaderboardRow
                  key={entry.name}
                  entry={entry}
                  rank={i + 1}
                  maxRunCount={maxUserRuns}
                />
              ))}
              {!showAllUsers && data.user_leaderboard.length > 20 && (
                <Button
                  variant="outline"
                  color="gray"
                  size="xs"
                  mt="sm"
                  onClick={() => setShowAllUsers(true)}
                >
                  Show all {data.user_leaderboard.length} users
                </Button>
              )}
            </>
          )}
        </Box>
      </Paper>
    </Box>
  );
}
