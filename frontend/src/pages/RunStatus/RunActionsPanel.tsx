import { Box, Button, Flex, Link, Text, TextField } from '@radix-ui/themes';
import { IconArrowRight, IconDownload } from '@tabler/icons-react';
import { Link as RouterLink } from 'react-router-dom';
import { SectionCard } from '../../components/SectionCard';
import { useDisclosure } from '../../hooks/useDisclosure';

interface Props {
  runId: number;
  adminPrefix: string;
  runHasArtifacts: boolean;
  isImmediateStart: boolean;
  supportEmail: string | undefined;
  nextPlaylistRunId: number | null;
}

// The primary call-to-action block for a finalised run: downloading artifacts, viewing the
// Active Power Chart, and (in a playlist) continuing to the next test. Kept visually distinct
// from AlertBox, which is reserved for genuine status messages (errors, skipped, not found).
export function RunActionsPanel({
  runId,
  adminPrefix,
  runHasArtifacts,
  isImmediateStart,
  supportEmail,
  nextPlaylistRunId,
}: Props) {
  return (
    <SectionCard title="Actions" tint="green">
      {runHasArtifacts ? (
        <Flex direction="column" gap="3">
          <Text as="p" color="gray" size="2">
            Download the artifacts for a PDF summary of the run, plus logs for debugging.
            {!isImmediateStart && (
              <>
                <br />
                Use the Active Power Chart to see the expected device response based on your
                client's behaviour during this test.
              </>
            )}
          </Text>
          <Flex align="center" gap="3" wrap="wrap">
            <Button asChild size="3">
              <a href={`${adminPrefix}/run/${runId}/artifact`}>
                <IconDownload size={16} />
                Download Artifacts
              </a>
            </Button>
            {!isImmediateStart && <ActivePowerChart runId={runId} adminPrefix={adminPrefix} />}
            {nextPlaylistRunId && (
              <Button asChild size="3" color="green" ml="auto">
                <RouterLink to={`${adminPrefix}/run/${nextPlaylistRunId}`}>
                  Go to Next Test
                  <IconArrowRight size={16} />
                </RouterLink>
              </Button>
            )}
          </Flex>
        </Flex>
      ) : (
        <Flex direction="column" gap="3" align="start">
          <Box>
            <Text as="p" color="amber">
              There are <b>no artifacts</b> recorded for this run due to an unexpected error
              during finalisation.
            </Text>
            <Text as="p">
              Please try re-running the test. If the problem persists contact support:{' '}
              <Link href={`mailto:${supportEmail}`}>{supportEmail}</Link>
            </Text>
          </Box>
          {nextPlaylistRunId && (
            <Button asChild size="3" color="green">
              <RouterLink to={`${adminPrefix}/run/${nextPlaylistRunId}`}>
                Go to Next Test
                <IconArrowRight size={16} />
              </RouterLink>
            </Button>
          )}
        </Flex>
      )}
    </SectionCard>
  );
}

// Disclosure wrapping a plain GET form that opens the power-limit chart in a new tab. The
// optional video_start (MM:SS) aligns the chart's time axis to an external video recording.
function ActivePowerChart({ runId, adminPrefix }: { runId: number; adminPrefix: string }) {
  const [opened, { toggle }] = useDisclosure(false);
  return (
    <Box>
      <Button variant="outline" color="gray" size="3" onClick={toggle}>
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
    </Box>
  );
}
