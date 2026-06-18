import { Alert, Anchor, Button, Table, Text, Title } from '@mantine/core';
import { useMutation } from '@tanstack/react-query';
import { IconCheck, IconMinus, IconPlayerPlay, IconX } from '@tabler/icons-react';
import { useState } from 'react';
import { ScrollCard } from '../../components/ScrollCard';
import { sendProceed } from '../../api/runStatus';
import type { CriteriaEntry, RunStatus, RunnerStatus, StepEventStatus } from '../../api/types';
import { formatDate, formatRelativeDate } from '../../utils/dates';
import { MetadataCard } from './MetadataCard';
import { RequestDetailsModal } from './RequestDetailsModal';
import { RequestsCard } from './RequestsCard';
import {
  activeStep,
  criteriaWithXsd,
  formatTimeLabel,
  isProceedStepActive,
  stepPhase,
} from './statusHelpers';
import { TimelineChart } from './TimelineChart';
import { XsdErrorsCard } from './XsdErrorsCard';

interface Props {
  status: RunnerStatus;
  runId: number;
  runStatus: RunStatus | null;
  runProcedureId: string | null;
  isAdminView: boolean;
}

// The live status panels of run_status.html (everything below the header card except the
// timeline charts, which land in 9d). Driven by the polled RunnerStatus.
export function LiveStatusPanels({ status, runId, runStatus, runProcedureId, isAdminView }: Props) {
  const [selectedRequest, setSelectedRequest] = useState<number | null>(null);
  const requests = status.request_history ?? [];

  return (
    <>
      <GeneralCard status={status} runProcedureId={runProcedureId} />
      {status.precondition_checks != null && (
        <CheckTableCard title="Precondition Checks" entries={status.precondition_checks} />
      )}
      <CheckTableCard title="Current Criteria" entries={criteriaWithXsd(status)} />
      <StepsCard status={status} runStatus={runStatus} runId={runId} isAdminView={isAdminView} />
      <TimelineChart
        timeline={status.timeline}
        stepStatus={status.step_status}
        requestHistory={requests}
        timestampStart={status.timestamp_start}
      />
      <MetadataCard metadata={status.end_device_metadata} />
      <RequestsCard requests={requests} onShowRequest={setSelectedRequest} />
      <XsdErrorsCard requests={requests} onShowRequest={setSelectedRequest} />
      <EnvoyLogsCard log={status.log_envoy} />

      <RequestDetailsModal
        runId={runId}
        requestId={selectedRequest}
        onClose={() => setSelectedRequest(null)}
      />
    </>
  );
}

function dateCell(iso: string) {
  const d = new Date(iso);
  return `${formatDate(d)} (${formatRelativeDate(d)})`;
}

// Procedure card with the General table (Started / Created / Last Interaction / Summary).
function GeneralCard({
  status,
  runProcedureId,
}: {
  status: RunnerStatus;
  runProcedureId: string | null;
}) {
  const interaction = status.last_client_interaction?.timestamp ?? null;
  return (
    <ScrollCard
      header={
        <Title order={5}>
          <Anchor href={`/procedure/${runProcedureId}`}>{runProcedureId}</Anchor>
        </Title>
      }
    >
      <Table>
        <Table.Tbody>
          {status.timestamp_start && (
            <Table.Tr>
              <Table.Th>Started</Table.Th>
              <Table.Td>{dateCell(status.timestamp_start)}</Table.Td>
            </Table.Tr>
          )}
          {status.timestamp_initialise && (
            <Table.Tr>
              <Table.Th>Created</Table.Th>
              <Table.Td>{dateCell(status.timestamp_initialise)}</Table.Td>
            </Table.Tr>
          )}
          {interaction && (
            <Table.Tr>
              <Table.Th>Last Interaction</Table.Th>
              <Table.Td>{dateCell(interaction)}</Table.Td>
            </Table.Tr>
          )}
          <Table.Tr>
            <Table.Th>Summary</Table.Th>
            <Table.Td>{status.status_summary}</Table.Td>
          </Table.Tr>
        </Table.Tbody>
      </Table>
    </ScrollCard>
  );
}

// Shared layout for the Precondition Checks and Current Criteria tables (type / icon / details).
function CheckTableCard({ title, entries }: { title: string; entries: CriteriaEntry[] }) {
  return (
    <ScrollCard header={<Title order={5}>{title}</Title>}>
      <Table>
        <Table.Tbody>
          {entries.map((c) => (
            <Table.Tr key={c.type}>
              <Table.Th>{c.type}</Table.Th>
              <Table.Td>
                {c.success ? (
                  <IconCheck size={16} color="var(--mantine-color-green-6)" />
                ) : (
                  <IconX size={16} color="var(--mantine-color-red-6)" />
                )}
              </Table.Td>
              <Table.Td>{c.details}</Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </ScrollCard>
  );
}

function StepIcon({ info }: { info: StepEventStatus }) {
  const phase = stepPhase(info);
  if (phase === 'resolved') return <IconCheck size={16} color="var(--mantine-color-green-6)" />;
  if (phase === 'active') return <IconPlayerPlay size={16} color="var(--mantine-color-blue-6)" />;
  return <IconMinus size={16} color="var(--mantine-color-gray-6)" />;
}

function completedCell(info: StepEventStatus, timestampStart: string | null) {
  if (stepPhase(info) !== 'resolved' || !info.completed_at || !timestampStart) return '';
  const completed = new Date(info.completed_at);
  const elapsed = Math.floor((completed.getTime() - new Date(timestampStart).getTime()) / 1000);
  const utc = completed
    .toISOString()
    .replace('T', ' ')
    .replace(/\.\d+Z$/, ' UTC');
  return <span title={utc}>{formatTimeLabel(elapsed)}</span>;
}

// "Steps" card: the per-step progress table plus, while started, the active step's
// instructions and (if blocked) the proceed button.
function StepsCard({
  status,
  runStatus,
  runId,
  isAdminView,
}: {
  status: RunnerStatus;
  runStatus: RunStatus | null;
  runId: number;
  isAdminView: boolean;
}) {
  const [proceededStep, setProceededStep] = useState<string | null>(null);
  const steps = Object.entries(status.step_status ?? {});
  const instructions = status.instructions ?? [];
  const active = activeStep(status.step_status);

  const proceedMutation = useMutation({
    mutationFn: () => sendProceed(runId, isAdminView),
    onSuccess: () => setProceededStep(active?.name ?? null),
  });

  const showInstructions = runStatus === 'started' && instructions.length > 0;
  const showProceed =
    isProceedStepActive(status.step_status) && active != null && active.name !== proceededStep;

  return (
    <ScrollCard header={<Title order={5}>Steps</Title>}>
      {showInstructions && (
        <Alert color="blue" mb="md">
          <ul>
            {instructions.map((i, idx) => (
              <li key={idx}>{i}</li>
            ))}
          </ul>
          {showProceed && (
            <Button onClick={() => proceedMutation.mutate()} loading={proceedMutation.isPending}>
              Proceed to next step →
            </Button>
          )}
          {proceedMutation.isError && (
            <Alert color="red" mt="md">
              There was an error proceeding to the next step. Please try again.
            </Alert>
          )}
        </Alert>
      )}

      <Table>
        <Table.Tbody>
          {steps.map(([name, info]) => (
            <Table.Tr key={name}>
              <Table.Th>{name}</Table.Th>
              <Table.Td>
                <Text span c="dimmed">
                  {info.event_status ?? ''}
                </Text>
              </Table.Td>
              <Table.Td>{completedCell(info, status.timestamp_start)}</Table.Td>
              <Table.Td>
                <StepIcon info={info} />
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </ScrollCard>
  );
}

function EnvoyLogsCard({ log }: { log: string }) {
  return (
    <ScrollCard header={<Title order={5}>Envoy Logs</Title>}>
      <pre style={{ margin: 0, whiteSpace: 'pre-wrap' }}>{log || 'No logs recorded'}</pre>
    </ScrollCard>
  );
}
