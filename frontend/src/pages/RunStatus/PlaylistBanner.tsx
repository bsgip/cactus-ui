import { Badge, Box, Button, Flex, IconButton, Separator, Text, Tooltip } from '@radix-ui/themes';
import {
  IconBan,
  IconCheck,
  IconClock,
  IconDownload,
  IconPlayerPlay,
  IconPlayerStop,
  IconRotateClockwise,
  IconX,
} from '@tabler/icons-react';
import type { ReactNode } from 'react';
import { Link as RouterLink } from 'react-router-dom';
import { useConfirm } from '../../components/useConfirm';
import { formatDate } from '../../utils/dates';
import { PlaylistEditDialog } from './PlaylistEditDialog';
import type { CurrentActiveRun, PlaylistRunRow, PlaylistView } from './runStatusModel';
import { usePlaylistRetry } from './usePlaylistRetry';

interface Props {
  playlistView: PlaylistView;
  currentActiveRun: CurrentActiveRun | null;
  runId: number;
  runProcedureId: string | null;
  isAdminView: boolean;
  isEnding: boolean;
  onEndPlaylist: () => void;
  onPlaylistUpdated: () => void;
}

const TERMINAL_STATUSES = ['finalised', 'skipped'];

function startedAtLabel(startedAt: string): string {
  const start = new Date(startedAt);
  const diffMins = Math.floor((Date.now() - start.getTime()) / 60000);
  return `${formatDate(start)} (${diffMins} minute${diffMins !== 1 ? 's' : ''} ago)`;
}

// Top playlist banner: per-run status badges (with passed/failed artifact downloads), the
// currently-viewed test, a jump-to-active-run button and End Playlist.
export function PlaylistBanner({
  playlistView,
  currentActiveRun,
  runId,
  runProcedureId,
  isAdminView,
  isEnding,
  onEndPlaylist,
  onPlaylistUpdated,
}: Props) {
  const { confirm, confirmDialog } = useConfirm();
  const adminPrefix = isAdminView ? '/admin' : '';
  const isComplete =
    playlistView.runs.filter((r) => TERMINAL_STATUSES.includes(r.status)).length ===
    playlistView.total;
  const isFinalTest =
    playlistView.current_order != null && playlistView.current_order >= playlistView.total - 1;
  const upcomingRuns = playlistView.runs.filter((r) => r.status === 'initialised');
  const activeRunId = currentActiveRun?.run_id ?? null;

  const confirmEndPlaylist = () =>
    confirm({
      title: 'End playlist',
      body: 'Are you sure you want to end the playlist? This will finalize the current test and mark all remaining tests as skipped.',
      confirmLabel: 'End Playlist',
      cancelLabel: 'Cancel',
      confirmColor: 'red',
      onConfirm: onEndPlaylist,
    });

  const { retry, retryNow, isRetrying, retryError } = usePlaylistRetry({
    runId,
    upcomingRuns,
    activeRunId,
    adminPrefix,
    onPlaylistUpdated,
  });

  const confirmRetryNow = (testProcedureId: string) =>
    confirm({
      title: 'Finalise and retry',
      body: `This will end the running ${testProcedureId} test now (its result is recorded as-is) and immediately start ${testProcedureId} again.`,
      confirmLabel: 'Finalise & Retry',
      cancelLabel: 'Cancel',
      onConfirm: () => retryNow(testProcedureId),
    });

  return (
    <Box
      role="alert"
      style={{
        backgroundColor: 'var(--blue-3)',
        border: '1px solid var(--blue-6)',
        borderRadius: 'var(--radius-3)',
        padding: 'var(--space-3)',
      }}
    >
      {confirmDialog}
      <Flex justify="between" align="center" mb="1" gap="2">
        <Text weight="bold">
          Playlist: {playlistView.name}
          {isComplete && ' (Finalised)'}
        </Text>
        <Flex gap="2" align="center">
          {currentActiveRun && currentActiveRun.run_id !== runId && (
            <Button size="1" asChild>
              <RouterLink to={`${adminPrefix}/run/${currentActiveRun.run_id}`}>
                <IconPlayerPlay size={14} />
                Go to active run ({currentActiveRun.test_procedure_id})
              </RouterLink>
            </Button>
          )}
          {!isComplete && activeRunId != null && (
            <PlaylistEditDialog
              runId={runId}
              upcomingRuns={upcomingRuns}
              activeRunId={activeRunId}
              runGroupId={playlistView.run_group_id}
              onUpdated={onPlaylistUpdated}
            />
          )}
          {!isComplete && (
            <Button size="1" color="red" loading={isEnding} onClick={confirmEndPlaylist}>
              <IconPlayerStop size={14} />
              End Playlist
            </Button>
          )}
        </Flex>
      </Flex>

      {playlistView.started_at && (
        <Text as="div" size="2" color="gray" mb="1">
          Started at: {startedAtLabel(playlistView.started_at)}
        </Text>
      )}

      <Separator size="4" my="1" />

      <Flex gap="2" align="start" mb="1" wrap="wrap">
        {playlistView.runs.map((run, index) => (
          <PlaylistRunBadge
            key={run.run_id}
            run={run}
            isCurrent={index === playlistView.current_order}
            adminPrefix={adminPrefix}
            onRetry={activeRunId != null ? () => retry(run.test_procedure_id) : undefined}
            onRetryNow={
              !isAdminView && run.run_id === activeRunId
                ? () => confirmRetryNow(run.test_procedure_id)
                : undefined
            }
            isRetrying={isRetrying}
          />
        ))}
      </Flex>

      {retryError && (
        <Text as="div" size="1" color="red" mb="1">
          {retryError}
        </Text>
      )}

      {playlistView.current_order != null && (
        <Text as="div" size="2" color="gray">
          Viewing: Test {playlistView.current_order + 1} of {playlistView.total} &mdash;{' '}
          {runProcedureId}
        </Text>
      )}

      {isFinalTest && (
        <>
          <Separator size="4" my="1" />
          <Text as="div" size="2" color="gray">
            This is the final test in the playlist.
          </Text>
        </>
      )}

      {!isComplete && activeRunId != null && (
        <>
          <Separator size="4" my="1" />
          <Text as="div" size="1" color="gray">
            You can still change this playlist while it runs: use the{' '}
            <IconRotateClockwise size={11} style={{ verticalAlign: 'middle' }} aria-hidden /> button
            to retry a failed test &mdash; or to cut short and rerun the one in progress &mdash; or
            use Edit Playlist to add, remove or reorder the upcoming tests.
          </Text>
        </>
      )}
    </Box>
  );
}

function PlaylistRunBadge({
  run,
  isCurrent,
  adminPrefix,
  onRetry,
  onRetryNow,
  isRetrying,
}: {
  run: PlaylistRunRow;
  isCurrent: boolean;
  adminPrefix: string;
  onRetry?: () => void;
  onRetryNow?: () => void;
  isRetrying: boolean;
}) {
  const href = `${adminPrefix}/run/${run.run_id}`;
  const passed = run.all_criteria_met;

  let badge: ReactNode;
  if (run.status === 'finalised') {
    badge = (
      <Flex gap="1" align="center">
        <Tooltip content={passed ? 'Passed' : 'Failed'}>
          <Badge asChild color={passed ? 'green' : 'red'}>
            <RouterLink to={href} style={{ cursor: 'pointer' }}>
              {passed ? <IconCheck size={12} /> : <IconX size={12} />}
              {run.test_procedure_id}
            </RouterLink>
          </Badge>
        </Tooltip>
        {run.has_artifacts && (
          <Tooltip content="Download artifacts">
            <IconButton
              asChild
              variant="outline"
              color={passed ? 'green' : 'red'}
              size="1"
              aria-label="Download artifacts"
            >
              <a href={`${adminPrefix}/run/${run.run_id}/artifact`}>
                <IconDownload size={12} />
              </a>
            </IconButton>
          </Tooltip>
        )}
        {!passed && onRetry && (
          <Tooltip content="Run this test again - it will be queued to run next">
            <IconButton
              variant="outline"
              color="red"
              size="1"
              aria-label="Retry"
              loading={isRetrying}
              onClick={onRetry}
            >
              <IconRotateClockwise size={12} />
            </IconButton>
          </Tooltip>
        )}
      </Flex>
    );
  } else if (run.status === 'started' || run.status === 'provisioning') {
    badge = (
      <Flex gap="1" align="center">
        <Tooltip content="Running">
          <Badge asChild color="blue">
            <RouterLink to={href} style={{ cursor: 'pointer' }}>
              <IconPlayerPlay size={12} />
              {run.test_procedure_id}
            </RouterLink>
          </Badge>
        </Tooltip>
        {onRetryNow && (
          <Tooltip content="Going badly? Finalise this test now and run it again">
            <IconButton
              variant="outline"
              color="blue"
              size="1"
              aria-label="Finalise and retry"
              loading={isRetrying}
              onClick={onRetryNow}
            >
              <IconRotateClockwise size={12} />
            </IconButton>
          </Tooltip>
        )}
      </Flex>
    );
  } else if (run.status === 'skipped') {
    badge = (
      <Tooltip content="Skipped">
        <Badge color="gray">
          <IconBan size={12} />
          {run.test_procedure_id}
        </Badge>
      </Tooltip>
    );
  } else if (run.status === 'initialised') {
    badge = (
      <Tooltip content="Queued - waiting for previous tests to complete">
        <Badge color="gray" variant="soft">
          <IconClock size={12} />
          {run.test_procedure_id}
        </Badge>
      </Tooltip>
    );
  } else {
    badge = (
      <Tooltip content="Pending">
        <Badge color="gray" variant="soft">
          {run.test_procedure_id}
        </Badge>
      </Tooltip>
    );
  }

  return (
    <Flex direction="column" gap="1">
      {badge}
      {isCurrent && (
        <div
          style={{ height: 3, width: '100%', borderRadius: 2, backgroundColor: 'var(--blue-9)' }}
        />
      )}
    </Flex>
  );
}
