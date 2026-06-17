import { Alert, Button, Card, Code, Text, Title } from '@mantine/core';
import type { RunStatus } from '../../api/types';

interface Props {
  runId: number;
  runStatus: RunStatus | null;
  runTestUri: string | null;
  instructions: string[];
  isAdminView: boolean;
  isStarting: boolean;
  isFinalising: boolean;
  onStart: () => void;
  onFinalise: () => void;
}

// Top card of the live run view: run id/status, the test URI, and the lifecycle button for
// the current phase (Start while initialised, Finalise while started). Both buttons are
// disabled in the admin view, mirroring the old user_buttons_state="disabled".
export function LiveHeaderCard({
  runId,
  runStatus,
  runTestUri,
  instructions,
  isAdminView,
  isStarting,
  isFinalising,
  onStart,
  onFinalise,
}: Props) {
  return (
    <Card withBorder>
      <Title order={4}>
        Run {runId} ({runStatus})
      </Title>

      <Text my="sm">
        <Code style={{ userSelect: 'all' }}>{runTestUri}</Code>
      </Text>

      {runStatus === 'initialised' &&
        (instructions.length === 0 ? (
          <>
            <Text mb="sm">
              This run is currently in the pre-start phase. It can be started at any time.
            </Text>
            <Button onClick={onStart} loading={isStarting} disabled={isAdminView}>
              Start
            </Button>
          </>
        ) : (
          <Alert color="blue">
            <Text>This run is currently in the pre-start phase.</Text>
            <Text mb="xs">Please ensure the following before starting the test:</Text>
            <ul>
              {instructions.map((i, idx) => (
                <li key={idx}>{i}</li>
              ))}
            </ul>
            <Button onClick={onStart} loading={isStarting} disabled={isAdminView}>
              Start
            </Button>
          </Alert>
        ))}

      {runStatus === 'started' && (
        <>
          <Text>
            The test is now underway - the server will have loaded any initial preconditions (eg:
            DERControls) and its now time for your client to respond appropriately.
          </Text>
          <Text my="sm">
            When you're ready to end the test, press the Finalise button. An artefact will be
            downloaded including a PDF report, request logs, and server logs to help with debugging.
          </Text>
          <Button color="yellow" onClick={onFinalise} loading={isFinalising} disabled={isAdminView}>
            Finalise
          </Button>
        </>
      )}
    </Card>
  );
}
