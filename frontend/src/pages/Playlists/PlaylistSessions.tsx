import { Anchor, Box, Button, Card, Group, Menu, Stack, Table, Text } from '@mantine/core';
import { modals } from '@mantine/modals';
import { IconDownload, IconPlayerPlay, IconPlayerStop } from '@tabler/icons-react';
import { Link } from 'react-router-dom';
import type { PlaylistSession, PlaylistTestStatus } from '../../api/types';
import { formatDate, formatRelativeDate } from '../../utils/dates';
import { StatusDots } from './StatusDots';
import { statusDots } from './statusDots';

interface PlaylistSessionsProps {
  sessions: PlaylistSession[];
  isFinalising: boolean;
  onFinalise: (runId: number) => void;
}

function testCountLabel(statuses: PlaylistTestStatus[]): string {
  return `${statuses.length} test${statuses.length !== 1 ? 's' : ''}`;
}

function DownloadMenu({ statuses }: { statuses: PlaylistTestStatus[] }) {
  const withArtifacts = statuses.filter((ts) => ts.has_artifacts);
  if (withArtifacts.length === 0) {
    return (
      <Button size="xs" variant="outline" color="gray" disabled aria-label="No artifacts">
        <IconDownload size={14} />
      </Button>
    );
  }

  const downloadAllHref = `/playlist/artifacts?run_ids=${withArtifacts.map((ts) => ts.run_id).join(',')}`;

  return (
    <Menu position="bottom-end">
      <Menu.Target>
        <Button size="xs" variant="outline" color="gray" aria-label="Download artifacts">
          <IconDownload size={14} />
        </Button>
      </Menu.Target>
      <Menu.Dropdown>
        {withArtifacts.map((ts) => (
          <Menu.Item key={ts.run_id} component="a" href={`/run/${ts.run_id}/artifact`}>
            #{ts.run_id} – {ts.test_procedure_id}
          </Menu.Item>
        ))}
        {withArtifacts.length > 1 && (
          <>
            <Menu.Divider />
            <Menu.Item
              component="a"
              href={downloadAllHref}
              leftSection={<IconDownload size={14} />}
            >
              Download All
            </Menu.Item>
          </>
        )}
      </Menu.Dropdown>
    </Menu>
  );
}

export function PlaylistSessions({ sessions, isFinalising, onFinalise }: PlaylistSessionsProps) {
  const active = sessions.filter((s) => s.is_active);
  const past = sessions.filter((s) => !s.is_active);

  const confirmFinalise = (runId: number) =>
    modals.openConfirmModal({
      title: 'Finalise playlist',
      children: (
        <Text size="sm">
          Finalise this playlist? The current test will be finalised and remaining tests skipped.
        </Text>
      ),
      labels: { confirm: 'Finalise Playlist', cancel: 'Cancel' },
      confirmProps: { color: 'red' },
      onConfirm: () => onFinalise(runId),
    });

  return (
    <>
      {active.length > 0 && (
        <>
          <Text fw={500} py={4}>
            Active Playlist
          </Text>
          <Stack gap="xs">
            {active.map((s) => {
              const { activeRunId } = statusDots(s.test_statuses);
              const goToRunId = activeRunId ?? s.first_run_id;
              return (
                <Card key={s.playlist_execution_id} padding="xs" bd="1px solid blue.5">
                  <Group gap="sm" wrap="wrap">
                    <div>
                      <Anchor component={Link} to={`/run/${s.first_run_id}`}>
                        <Text span ff="monospace">
                          {s.short_id}
                        </Text>
                      </Anchor>
                      <Text component="small" size="xs" c="dimmed" ml={6}>
                        {testCountLabel(s.test_statuses)}
                      </Text>
                    </div>
                    <Text size="sm" c="dimmed">
                      {formatDate(new Date(s.created_at))}
                    </Text>
                    <Box flex={1}>
                      <StatusDots testStatuses={s.test_statuses} />
                    </Box>
                    <Button
                      size="xs"
                      component={Link}
                      to={`/run/${goToRunId}`}
                      leftSection={<IconPlayerPlay size={14} />}
                    >
                      Go to run
                    </Button>
                    <Button
                      size="xs"
                      color="red"
                      loading={isFinalising}
                      onClick={() => confirmFinalise(goToRunId)}
                      leftSection={<IconPlayerStop size={14} />}
                    >
                      Finalise Playlist
                    </Button>
                  </Group>
                </Card>
              );
            })}
          </Stack>
        </>
      )}

      <Text fw={500} py={4}>
        Past Sessions
      </Text>
      {past.length === 0 ? (
        <Text c="dimmed">No past playlist sessions.</Text>
      ) : (
        <Table>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Session</Table.Th>
              <Table.Th>Date</Table.Th>
              <Table.Th>Status</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {past.map((s) => {
              const created = new Date(s.created_at);
              return (
                <Table.Tr key={s.playlist_execution_id}>
                  <Table.Td>
                    <Anchor component={Link} to={`/run/${s.first_run_id}`}>
                      <Text span ff="monospace">
                        {s.short_id}
                      </Text>
                    </Anchor>
                    <br />
                    <Text component="small" size="xs" c="dimmed">
                      {testCountLabel(s.test_statuses)}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    {formatDate(created)}
                    <br />
                    <Text component="small" size="xs" c="dimmed">
                      {formatRelativeDate(created)}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <StatusDots testStatuses={s.test_statuses} />
                  </Table.Td>
                  <Table.Td align="right">
                    <DownloadMenu statuses={s.test_statuses} />
                  </Table.Td>
                </Table.Tr>
              );
            })}
          </Table.Tbody>
        </Table>
      )}
    </>
  );
}
