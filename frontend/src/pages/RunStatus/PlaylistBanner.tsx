import { ActionIcon, Alert, Badge, Button, Divider, Group, Stack, Text, Tooltip } from '@mantine/core';
import { modals } from '@mantine/modals';
import {
  IconBan,
  IconCheck,
  IconClock,
  IconDownload,
  IconPlayerPlay,
  IconPlayerStop,
  IconX,
} from '@tabler/icons-react';
import type { ReactNode } from 'react';
import type { CurrentActiveRun, PlaylistRunDisplay, RunStatusPlaylistInfo } from '../../api/types';
import { formatDate } from '../../utils/dates';

interface Props {
  playlistInfo: RunStatusPlaylistInfo;
  currentActiveRun: CurrentActiveRun | null;
  runId: number;
  runProcedureId: string | null;
  isAdminView: boolean;
  isEnding: boolean;
  onEndPlaylist: () => void;
}

const TERMINAL_STATUSES = ['finalised', 'skipped'];

function startedAtLabel(startedAt: string): string {
  const start = new Date(startedAt);
  const diffMins = Math.floor((Date.now() - start.getTime()) / 60000);
  return `${formatDate(start)} (${diffMins} minute${diffMins !== 1 ? 's' : ''} ago)`;
}

// Top playlist banner from run_status.html: per-run status badges (with passed/failed artifact
// downloads), the currently-viewed test, a jump-to-active-run button and End Playlist.
export function PlaylistBanner({
  playlistInfo,
  currentActiveRun,
  runId,
  runProcedureId,
  isAdminView,
  isEnding,
  onEndPlaylist,
}: Props) {
  const adminPrefix = isAdminView ? '/admin' : '';
  const isComplete =
    playlistInfo.runs.filter((r) => TERMINAL_STATUSES.includes(r.status)).length ===
    playlistInfo.total;
  const isFinalTest =
    playlistInfo.current_order != null && playlistInfo.current_order >= playlistInfo.total - 1;

  const confirmEndPlaylist = () =>
    modals.openConfirmModal({
      title: 'End playlist',
      children: (
        <Text size="sm">
          Are you sure you want to end the playlist? This will finalize the current test and mark all
          remaining tests as skipped.
        </Text>
      ),
      labels: { confirm: 'End Playlist', cancel: 'Cancel' },
      confirmProps: { color: 'red' },
      onConfirm: onEndPlaylist,
    });

  return (
    <Alert color="blue" role="alert">
      <Group justify="space-between" mb="xs" wrap="nowrap">
        <Text fw={700}>
          Playlist: {playlistInfo.name}
          {isComplete && ' (Finalised)'}
        </Text>
        <Group gap="xs">
          {currentActiveRun && currentActiveRun.run_id !== runId && (
            <Button
              size="xs"
              component="a"
              href={`${adminPrefix}/run/${currentActiveRun.run_id}`}
              leftSection={<IconPlayerPlay size={14} />}
            >
              Go to active run ({currentActiveRun.test_procedure_id})
            </Button>
          )}
          {!isComplete && (
            <Button
              size="xs"
              color="red"
              loading={isEnding}
              onClick={confirmEndPlaylist}
              leftSection={<IconPlayerStop size={14} />}
            >
              End Playlist
            </Button>
          )}
        </Group>
      </Group>

      {playlistInfo.started_at && (
        <Text size="sm" c="dimmed" mb="xs">
          Started at: {startedAtLabel(playlistInfo.started_at)}
        </Text>
      )}

      <Divider my="xs" />

      <Group gap="xs" align="flex-start" mb="xs">
        {playlistInfo.runs.map((run, index) => (
          <PlaylistRunBadge
            key={run.run_id}
            run={run}
            isCurrent={index === playlistInfo.current_order}
            adminPrefix={adminPrefix}
          />
        ))}
      </Group>

      {playlistInfo.current_order != null && (
        <Text size="sm" c="dimmed">
          Viewing: Test {playlistInfo.current_order + 1} of {playlistInfo.total} &mdash;{' '}
          {runProcedureId}
        </Text>
      )}

      {isFinalTest && (
        <>
          <Divider my="xs" />
          <Text size="sm" c="dimmed">
            This is the final test in the playlist.
          </Text>
        </>
      )}
    </Alert>
  );
}

function PlaylistRunBadge({
  run,
  isCurrent,
  adminPrefix,
}: {
  run: PlaylistRunDisplay;
  isCurrent: boolean;
  adminPrefix: string;
}) {
  const href = `${adminPrefix}/run/${run.run_id}`;
  const passed = run.all_criteria_met;

  let badge: ReactNode;
  if (run.status === 'finalised') {
    badge = (
      <Group gap={4} wrap="nowrap">
        <Tooltip label={passed ? 'Passed' : 'Failed'} withArrow>
          <Badge
            component="a"
            href={href}
            color={passed ? 'green' : 'red'}
            style={{ cursor: 'pointer' }}
            leftSection={passed ? <IconCheck size={12} /> : <IconX size={12} />}
          >
            {run.test_procedure_id}
          </Badge>
        </Tooltip>
        {run.has_artifacts && (
          <Tooltip label="Download artifacts" withArrow>
            <ActionIcon
              component="a"
              href={`${adminPrefix}/run/${run.run_id}/artifact`}
              variant="outline"
              color={passed ? 'green' : 'red'}
              size="sm"
              aria-label="Download artifacts"
            >
              <IconDownload size={12} />
            </ActionIcon>
          </Tooltip>
        )}
      </Group>
    );
  } else if (run.status === 'started' || run.status === 'provisioning') {
    badge = (
      <Tooltip label="Running" withArrow>
        <Badge
          component="a"
          href={href}
          color="blue"
          style={{ cursor: 'pointer' }}
          leftSection={<IconPlayerPlay size={12} />}
        >
          {run.test_procedure_id}
        </Badge>
      </Tooltip>
    );
  } else if (run.status === 'skipped') {
    badge = (
      <Tooltip label="Skipped" withArrow>
        <Badge color="gray" leftSection={<IconBan size={12} />}>
          {run.test_procedure_id}
        </Badge>
      </Tooltip>
    );
  } else if (run.status === 'initialised') {
    badge = (
      <Tooltip label="Queued - waiting for previous tests to complete" withArrow>
        <Badge color="gray" variant="light" leftSection={<IconClock size={12} />}>
          {run.test_procedure_id}
        </Badge>
      </Tooltip>
    );
  } else {
    badge = (
      <Tooltip label="Pending" withArrow>
        <Badge color="gray" variant="light">
          {run.test_procedure_id}
        </Badge>
      </Tooltip>
    );
  }

  return (
    <Stack gap={2}>
      {badge}
      {isCurrent && (
        <div
          style={{
            height: 3,
            width: '100%',
            borderRadius: 2,
            backgroundColor: 'var(--mantine-color-blue-6)',
          }}
        />
      )}
    </Stack>
  );
}
