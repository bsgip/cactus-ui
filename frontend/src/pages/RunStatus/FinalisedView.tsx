import { Alert, Anchor, Button, Group, Stack, Text, TextInput, Title } from '@mantine/core';
import { useDisclosure } from '../../hooks/useDisclosure';
import { IconArrowRight, IconCircleCheck } from '@tabler/icons-react';
import { Link } from 'react-router-dom';
import type { RunStatus } from '../../api/types';

interface Props {
  runId: number;
  runStatus: RunStatus | null;
  runHasArtifacts: boolean | null;
  isImmediateStart: boolean;
  nextPlaylistRunId: number | null;
  supportEmail: string | undefined;
  isAdminView: boolean;
}

// The non-live run view: Not Found / Skipped / Finalised.
// Finalised runs offer an artifact download (browser-native GET route) and, unless this is
// an immediate-start procedure, an optional Active Power Chart with a video-start offset.
export function FinalisedView({
  runId,
  runStatus,
  runHasArtifacts,
  isImmediateStart,
  nextPlaylistRunId,
  supportEmail,
  isAdminView,
}: Props) {
  const adminPrefix = isAdminView ? '/admin' : '';

  return (
    <Stack>
      {runStatus == null && (
        <>
          <Title order={2}>Run {runId} Not Found</Title>
          <Alert color="red" role="alert">
            Run <strong>{runId}</strong> does not exist.
          </Alert>
        </>
      )}

      {runStatus === 'skipped' && (
        <>
          <Title order={2}>Run {runId} [Skipped]</Title>
          <Alert color="gray" role="alert">
            <Text>This run was skipped as part of a playlist and was never executed.</Text>
            <Text>No artifacts are available for skipped runs.</Text>
          </Alert>
        </>
      )}

      {runStatus != null && runStatus !== 'skipped' && (
        <>
          <Title order={2}>Run {runId} [Finalised]</Title>
          {runHasArtifacts ? (
            <Alert color="blue" role="alert">
              <Text>This run has been finalised and is no longer active.</Text>
              <Text mb="sm">
                Click below to download the run's artifacts
                {!isImmediateStart && ' or view the Active Power Chart'}.
              </Text>
              <Group align="flex-start">
                <Button component="a" href={`${adminPrefix}/run/${runId}/artifact`}>
                  Download Artifacts
                </Button>
                {!isImmediateStart && <ActivePowerChart runId={runId} adminPrefix={adminPrefix} />}
              </Group>
            </Alert>
          ) : (
            <Alert color="yellow" role="alert">
              <Text>This run has been finalised and is no longer active.</Text>
              <Text>
                There are <b>no artifacts</b> recorded for this run due to an unexpected error
                during finalisation.
              </Text>
              <Text>
                Please try re-running the test. If the problem persists contact support:{' '}
                <Anchor href={`mailto:${supportEmail}`}>{supportEmail}</Anchor>
              </Text>
            </Alert>
          )}
        </>
      )}

      {nextPlaylistRunId && (
        <Alert color="green" role="alert" icon={<IconCircleCheck size={18} />} title="Test Complete!">
          <Text mb="sm">
            This test has been completed. Click below to proceed to the next test in the playlist.
          </Text>
          <Button
            color="green"
            component={Link}
            to={`${adminPrefix}/run/${nextPlaylistRunId}`}
            rightSection={<IconArrowRight size={16} />}
          >
            Go to Next Test
          </Button>
        </Alert>
      )}
    </Stack>
  );
}

// Disclosure wrapping a plain GET form that opens the power-limit chart in a new tab. The
// optional video_start (MM:SS) aligns the chart's time axis to an external video recording.
function ActivePowerChart({ runId, adminPrefix }: { runId: number; adminPrefix: string }) {
  const [opened, { toggle }] = useDisclosure(false);
  return (
    <div>
      <Button variant="outline" color="gray" onClick={toggle}>
        Active Power Chart
      </Button>
      {opened && (
        <form
          action={`${adminPrefix}/run/${runId}/html_report`}
          method="GET"
          target="_blank"
          style={{
            marginTop: 'var(--mantine-spacing-xs)',
            width: 280,
          }}
        >
          <Stack
            gap="xs"
            p="sm"
            style={{
              border: '1px solid var(--mantine-color-gray-3)',
              borderRadius: 'var(--mantine-radius-sm)',
            }}
          >
            <Text size="sm">
              Optionally align the time axis to a video recording. Enter the video timestamp (MM:SS)
              at which the test started.
            </Text>
            <TextInput
              name="video_start"
              label="Video timestamp"
              placeholder="MM:SS"
              autoComplete="off"
              w={120}
            />
            <Button type="submit" variant="outline" color="gray" size="sm" style={{ alignSelf: 'flex-start' }}>
              Create Chart
            </Button>
          </Stack>
        </form>
      )}
    </div>
  );
}
