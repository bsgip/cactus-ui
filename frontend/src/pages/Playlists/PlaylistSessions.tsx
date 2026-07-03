import {
  Box,
  Button,
  Card,
  Code,
  DropdownMenu,
  Flex,
  Heading,
  Link,
  Table,
  Text,
} from '@radix-ui/themes';
import { IconDownload, IconPlayerPlay, IconPlayerStop } from '@tabler/icons-react';
import { Link as RouterLink } from 'react-router-dom';
import type { PlaylistSession, PlaylistTestStatus } from '../../api/types';
import { useConfirm } from '../../components/useConfirm';
import { formatDate, formatRelativeDate } from '../../utils/dates';
import { StatusDots } from './StatusDots';
import { statusDots } from './statusDots';

function testCountLabel(statuses: PlaylistTestStatus[]): string {
  return `${statuses.length} test${statuses.length !== 1 ? 's' : ''}`;
}

function DownloadMenu({ statuses }: { statuses: PlaylistTestStatus[] }) {
  const withArtifacts = statuses.filter((ts) => ts.has_artifacts);
  if (withArtifacts.length === 0) {
    return (
      <Button size="1" variant="outline" color="gray" disabled aria-label="No artifacts">
        <IconDownload size={14} />
      </Button>
    );
  }

  const downloadAllHref = `/playlist/artifacts?run_ids=${withArtifacts.map((ts) => ts.run_id).join(',')}`;

  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger>
        <Button size="1" variant="outline" color="gray" aria-label="Download artifacts">
          <IconDownload size={14} />
        </Button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Content align="end">
        {withArtifacts.map((ts) => (
          <DropdownMenu.Item key={ts.run_id} asChild>
            <a href={`/run/${ts.run_id}/artifact`}>
              #{ts.run_id} – {ts.test_procedure_id}
            </a>
          </DropdownMenu.Item>
        ))}
        {withArtifacts.length > 1 && (
          <>
            <DropdownMenu.Separator />
            <DropdownMenu.Item asChild>
              <a href={downloadAllHref}>
                <IconDownload size={14} /> Download All
              </a>
            </DropdownMenu.Item>
          </>
        )}
      </DropdownMenu.Content>
    </DropdownMenu.Root>
  );
}

interface ActivePlaylistsProps {
  sessions: PlaylistSession[];
  isFinalising: boolean;
  onFinalise: (runId: number) => void;
}

// Live monitor for the currently-running playlist(s). Promoted to the top of the page so it
// is the first thing visible while a playlist is in progress.
export function ActivePlaylists({ sessions, isFinalising, onFinalise }: ActivePlaylistsProps) {
  const { confirm, confirmDialog } = useConfirm();

  const confirmFinalise = (runId: number) =>
    confirm({
      title: 'Finalise playlist',
      body: 'Finalise this playlist? The current test will be finalised and remaining tests skipped.',
      confirmLabel: 'Finalise Playlist',
      cancelLabel: 'Cancel',
      confirmColor: 'red',
      onConfirm: () => onFinalise(runId),
    });

  return (
    <>
      {confirmDialog}
      <Heading as="h3" size="4" mb="2">
        Active Playlist
      </Heading>
      <Flex direction="column" gap="2">
        {sessions.map((s) => {
          const { activeRunId } = statusDots(s.test_statuses);
          const goToRunId = activeRunId ?? s.first_run_id;
          return (
            <Card key={s.playlist_execution_id} style={{ border: '1px solid var(--blue-7)' }}>
              <Flex gap="2" align="center" wrap="wrap">
                <div>
                  <Link asChild>
                    <RouterLink to={`/run/${s.first_run_id}`}>
                      <Code variant="ghost">{s.short_id}</Code>
                    </RouterLink>
                  </Link>
                  <Text size="1" color="gray" ml="2">
                    {testCountLabel(s.test_statuses)}
                  </Text>
                </div>
                <Text size="2" color="gray">
                  {formatDate(new Date(s.created_at))}
                </Text>
                <Box style={{ flex: 1 }}>
                  <StatusDots testStatuses={s.test_statuses} />
                </Box>
                <Button size="1" asChild>
                  <RouterLink to={`/run/${goToRunId}`}>
                    <IconPlayerPlay size={14} />
                    Go to run
                  </RouterLink>
                </Button>
                <Button
                  size="1"
                  color="red"
                  loading={isFinalising}
                  onClick={() => confirmFinalise(goToRunId)}
                >
                  <IconPlayerStop size={14} />
                  Finalise Playlist
                </Button>
              </Flex>
            </Card>
          );
        })}
      </Flex>
    </>
  );
}

interface PastSessionsProps {
  sessions: PlaylistSession[];
}

export function PastSessions({ sessions }: PastSessionsProps) {
  return (
    <>
      <Text as="div" weight="medium" my="1">
        Past Sessions
      </Text>
      {sessions.length === 0 ? (
        <Text color="gray">No past playlist sessions.</Text>
      ) : (
        <Table.Root variant="surface">
          <Table.Header>
            <Table.Row>
              <Table.ColumnHeaderCell>Session</Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell>Date</Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell>Status</Table.ColumnHeaderCell>
              <Table.ColumnHeaderCell />
            </Table.Row>
          </Table.Header>
          <Table.Body>
            {sessions.map((s) => {
              const created = new Date(s.created_at);
              return (
                <Table.Row key={s.playlist_execution_id}>
                  <Table.Cell>
                    <Link asChild>
                      <RouterLink to={`/run/${s.first_run_id}`}>
                        <Code variant="ghost">{s.short_id}</Code>
                      </RouterLink>
                    </Link>
                    <br />
                    <Text size="1" color="gray">
                      {testCountLabel(s.test_statuses)}
                    </Text>
                  </Table.Cell>
                  <Table.Cell>
                    {formatDate(created)}
                    <br />
                    <Text size="1" color="gray">
                      {formatRelativeDate(created)}
                    </Text>
                  </Table.Cell>
                  <Table.Cell>
                    <StatusDots testStatuses={s.test_statuses} />
                  </Table.Cell>
                  <Table.Cell style={{ textAlign: 'right' }}>
                    <DownloadMenu statuses={s.test_statuses} />
                  </Table.Cell>
                </Table.Row>
              );
            })}
          </Table.Body>
        </Table.Root>
      )}
    </>
  );
}
