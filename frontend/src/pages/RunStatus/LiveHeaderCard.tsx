import { Badge, Box, Button, Card, Code, Flex, Heading, Text } from '@radix-ui/themes';
import { IconAlertTriangle } from '@tabler/icons-react';
import type { RunStatus } from '../../api/types';

interface Props {
  runId: number;
  runStatus: RunStatus | null;
  runTestUri: string | null;
  instructions: string[];
  isAdminView: boolean;
  isStarting: boolean;
  isFinalising: boolean;
  warningCount: number;
  onStart: () => void;
  onFinalise: () => void;
}

// Top card of the live run view: run id/status, the test URI, and the lifecycle button for
// the current phase (Start while initialised, Finalise while started). Both buttons are
// disabled in the admin view.
export function LiveHeaderCard({
  runId,
  runStatus,
  runTestUri,
  instructions,
  isAdminView,
  isStarting,
  isFinalising,
  warningCount,
  onStart,
  onFinalise,
}: Props) {
  return (
    <Card>
      <Flex align="center" gap="2">
        <Heading as="h4" size="4">
          Run {runId} ({runStatus})
        </Heading>
        {warningCount > 0 && (
          <Badge color="amber">
            <IconAlertTriangle size={12} /> {warningCount} warning{warningCount === 1 ? '' : 's'}
          </Badge>
        )}
      </Flex>

      <Text as="p" my="2">
        <Code
          style={{
            userSelect: 'all',
            backgroundColor: 'var(--blue-2)',
            color: 'var(--blue-11)',
            border: '1px solid var(--blue-5)',
            padding: '2px 8px',
          }}
        >
          {runTestUri}
        </Code>
      </Text>

      {runStatus === 'initialised' &&
        (instructions.length === 0 ? (
          <>
            <Text as="p" mb="2">
              This run is currently in the pre-start phase. It can be started at any time.
            </Text>
            <Button
              onClick={onStart}
              loading={isStarting}
              disabled={isAdminView}
              style={{ width: 'fit-content' }}
            >
              Start
            </Button>
          </>
        ) : (
          <Box
            style={{
              backgroundColor: 'var(--blue-3)',
              border: '1px solid var(--blue-6)',
              borderRadius: 'var(--radius-3)',
              padding: 'var(--space-3)',
            }}
          >
            <Text as="p">This run is currently in the pre-start phase.</Text>
            <Text as="p" mb="1">
              Please ensure the following before starting the test:
            </Text>
            <ul>
              {instructions.map((i, idx) => (
                <li key={idx}>{i}</li>
              ))}
            </ul>
            <Button
              onClick={onStart}
              loading={isStarting}
              disabled={isAdminView}
              style={{ width: 'fit-content' }}
            >
              Start
            </Button>
          </Box>
        ))}

      {runStatus === 'started' && (
        <>
          <Text as="p">
            The test is now underway - the server will have loaded any initial preconditions (eg:
            DERControls) and its now time for your client to respond appropriately.
          </Text>
          <Text as="p" my="2">
            When you're ready to end the test, press the Finalise button. An artefact will be
            downloaded including a PDF report, request logs, and server logs to help with debugging.
          </Text>
          <Button
            color="amber"
            onClick={onFinalise}
            loading={isFinalising}
            disabled={isAdminView}
            style={{ width: 'fit-content' }}
          >
            Finalise
          </Button>
        </>
      )}
    </Card>
  );
}
