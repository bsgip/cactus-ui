import { Box, Flex, Heading, Text } from '@radix-ui/themes';
import type { RunResponse } from '../../api/types';
import { RunActionsPanel } from './RunActionsPanel';
import { RunSummaryPanel } from './RunSummaryPanel';

interface Props {
  runId: number;
  run: RunResponse | null;
  nextPlaylistRunId: number | null;
  supportEmail: string | undefined;
  isAdminView: boolean;
}

// Tinted alert box (Radix has no Alert; Callout can't hold buttons/multi-paragraph cleanly).
function AlertBox({
  color,
  children,
}: {
  color: 'red' | 'gray';
  children: React.ReactNode;
}) {
  return (
    <Box
      role="alert"
      style={{
        backgroundColor: `var(--${color}-3)`,
        border: `1px solid var(--${color}-6)`,
        borderRadius: 'var(--radius-3)',
        padding: 'var(--space-3)',
      }}
    >
      {children}
    </Box>
  );
}

// The non-live run view: Not Found / Skipped / Finalised.
// Finalised runs offer an artifact download (browser-native GET route) and, unless this is
// an immediate-start procedure, an optional Active Power Chart with a video-start offset.
export function FinalisedView({
  runId,
  run,
  nextPlaylistRunId,
  supportEmail,
  isAdminView,
}: Props) {
  const adminPrefix = isAdminView ? '/admin' : '';
  const runStatus = run?.status ?? null;
  const runHasArtifacts = run?.has_artifacts ?? null;
  const isImmediateStart = run?.immediate_start ?? false;

  return (
    <Flex direction="column" gap="3">
      {runStatus == null && (
        <>
          <Heading as="h2" size="6">
            Run {runId} Not Found
          </Heading>
          <AlertBox color="red">
            Run <strong>{runId}</strong> does not exist.
          </AlertBox>
        </>
      )}

      {runStatus === 'skipped' && (
        <>
          <Heading as="h2" size="6">
            Run {runId} [Skipped]
          </Heading>
          <AlertBox color="gray">
            <Text as="p">This run was skipped as part of a playlist and was never executed.</Text>
            <Text as="p">No artifacts are available for skipped runs.</Text>
          </AlertBox>
        </>
      )}

      {runStatus != null && runStatus !== 'skipped' && (
        <>
          <Heading as="h2" size="6">
            Run {runId} [Finalised]
          </Heading>
          <RunActionsPanel
            runId={runId}
            adminPrefix={adminPrefix}
            runHasArtifacts={!!runHasArtifacts}
            isImmediateStart={isImmediateStart}
            supportEmail={supportEmail}
            nextPlaylistRunId={nextPlaylistRunId}
          />
          {run && <RunSummaryPanel run={run} />}
        </>
      )}
    </Flex>
  );
}
