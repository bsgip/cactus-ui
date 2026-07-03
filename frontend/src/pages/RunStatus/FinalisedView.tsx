import { Box, Button, Flex, Heading, Link, Text, TextField } from '@radix-ui/themes';
import { IconArrowRight, IconCircleCheck } from '@tabler/icons-react';
import { Link as RouterLink } from 'react-router-dom';
import type { RunStatus } from '../../api/types';
import { useDisclosure } from '../../hooks/useDisclosure';

interface Props {
  runId: number;
  runStatus: RunStatus | null;
  runHasArtifacts: boolean | null;
  isImmediateStart: boolean;
  nextPlaylistRunId: number | null;
  supportEmail: string | undefined;
  isAdminView: boolean;
}

// Tinted alert box (Radix has no Alert; Callout can't hold buttons/multi-paragraph cleanly).
function AlertBox({
  color,
  children,
}: {
  color: 'red' | 'gray' | 'blue' | 'yellow' | 'green';
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
  runStatus,
  runHasArtifacts,
  isImmediateStart,
  nextPlaylistRunId,
  supportEmail,
  isAdminView,
}: Props) {
  const adminPrefix = isAdminView ? '/admin' : '';

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
          {runHasArtifacts ? (
            <AlertBox color="blue">
              <Text as="p">This run has been finalised and is no longer active.</Text>
              <Text as="p" mb="2">
                Click below to download the run's artifacts
                {!isImmediateStart && ' or view the Active Power Chart'}.
              </Text>
              <Flex align="start" gap="2">
                <Button asChild>
                  <a href={`${adminPrefix}/run/${runId}/artifact`}>Download Artifacts</a>
                </Button>
                {!isImmediateStart && <ActivePowerChart runId={runId} adminPrefix={adminPrefix} />}
              </Flex>
            </AlertBox>
          ) : (
            <AlertBox color="yellow">
              <Text as="p">This run has been finalised and is no longer active.</Text>
              <Text as="p">
                There are <b>no artifacts</b> recorded for this run due to an unexpected error
                during finalisation.
              </Text>
              <Text as="p">
                Please try re-running the test. If the problem persists contact support:{' '}
                <Link href={`mailto:${supportEmail}`}>{supportEmail}</Link>
              </Text>
            </AlertBox>
          )}
        </>
      )}

      {nextPlaylistRunId && (
        <AlertBox color="green">
          <Flex gap="2" align="start">
            <IconCircleCheck size={18} style={{ flexShrink: 0, marginTop: 2 }} />
            <div>
              <Text as="div" weight="bold" mb="1">
                Test Complete!
              </Text>
              <Text as="p" mb="2">
                This test has been completed. Click below to proceed to the next test in the
                playlist.
              </Text>
              <Button color="green" asChild>
                <RouterLink to={`${adminPrefix}/run/${nextPlaylistRunId}`}>
                  Go to Next Test
                  <IconArrowRight size={16} />
                </RouterLink>
              </Button>
            </div>
          </Flex>
        </AlertBox>
      )}
    </Flex>
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
          style={{ marginTop: 'var(--space-2)', width: 280 }}
        >
          <Flex
            direction="column"
            gap="2"
            p="3"
            style={{ border: '1px solid var(--gray-5)', borderRadius: 'var(--radius-2)' }}
          >
            <Text size="2">
              Optionally align the time axis to a video recording. Enter the video timestamp (MM:SS)
              at which the test started.
            </Text>
            <Text as="label" size="2">
              Video timestamp
              <TextField.Root name="video_start" placeholder="MM:SS" autoComplete="off" />
            </Text>
            <Button
              type="submit"
              variant="outline"
              color="gray"
              size="2"
              style={{ alignSelf: 'flex-start' }}
            >
              Create Chart
            </Button>
          </Flex>
        </form>
      )}
    </div>
  );
}
