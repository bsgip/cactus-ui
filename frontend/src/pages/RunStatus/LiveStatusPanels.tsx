import { Box, Button, Callout, Link, Table, Text } from '@radix-ui/themes';
import { useMutation } from '@tanstack/react-query';
import { IconCheck, IconMinus, IconPlayerPlay, IconX } from '@tabler/icons-react';
import { useState } from 'react';
import { SectionCard } from '../../components/SectionCard';
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

// The live status panels below the header card, driven by the polled RunnerStatus.
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
    <SectionCard
      scroll
      title={
        <Link href={`/procedure/${runProcedureId}`} weight="bold">
          {runProcedureId}
        </Link>
      }
    >
      <Table.Root>
        <Table.Body>
          {status.timestamp_start && (
            <Table.Row>
              <Table.RowHeaderCell>Started</Table.RowHeaderCell>
              <Table.Cell>{dateCell(status.timestamp_start)}</Table.Cell>
            </Table.Row>
          )}
          {status.timestamp_initialise && (
            <Table.Row>
              <Table.RowHeaderCell>Created</Table.RowHeaderCell>
              <Table.Cell>{dateCell(status.timestamp_initialise)}</Table.Cell>
            </Table.Row>
          )}
          {interaction && (
            <Table.Row>
              <Table.RowHeaderCell>Last Interaction</Table.RowHeaderCell>
              <Table.Cell>{dateCell(interaction)}</Table.Cell>
            </Table.Row>
          )}
          <Table.Row>
            <Table.RowHeaderCell>Summary</Table.RowHeaderCell>
            <Table.Cell>{status.status_summary}</Table.Cell>
          </Table.Row>
        </Table.Body>
      </Table.Root>
    </SectionCard>
  );
}

// Shared layout for the Precondition Checks and Current Criteria tables (type / icon / details).
function CheckTableCard({ title, entries }: { title: string; entries: CriteriaEntry[] }) {
  return (
    <SectionCard scroll title={title}>
      <Table.Root>
        <Table.Body>
          {entries.map((c) => (
            <Table.Row key={c.type}>
              <Table.RowHeaderCell>{c.type}</Table.RowHeaderCell>
              <Table.Cell>
                {c.success ? (
                  <IconCheck size={16} color="var(--green-9)" />
                ) : (
                  <IconX size={16} color="var(--red-9)" />
                )}
              </Table.Cell>
              <Table.Cell>{c.details}</Table.Cell>
            </Table.Row>
          ))}
        </Table.Body>
      </Table.Root>
    </SectionCard>
  );
}

function StepIcon({ info }: { info: StepEventStatus }) {
  const phase = stepPhase(info);
  if (phase === 'resolved') return <IconCheck size={16} color="var(--green-9)" />;
  if (phase === 'active') return <IconPlayerPlay size={16} color="var(--blue-9)" />;
  return <IconMinus size={16} color="var(--gray-9)" />;
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
    <SectionCard scroll title="Steps">
      {showInstructions && (
        <Box
          mb="3"
          style={{
            backgroundColor: 'var(--blue-3)',
            border: '1px solid var(--blue-6)',
            borderRadius: 'var(--radius-3)',
            padding: 'var(--space-3)',
          }}
        >
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
            <Callout.Root color="red" mt="3">
              <Callout.Text>
                There was an error proceeding to the next step. Please try again.
              </Callout.Text>
            </Callout.Root>
          )}
        </Box>
      )}

      <Table.Root>
        <Table.Body>
          {steps.map(([name, info]) => (
            <Table.Row key={name}>
              <Table.RowHeaderCell>{name}</Table.RowHeaderCell>
              <Table.Cell>
                <Text color="gray">{info.event_status ?? ''}</Text>
              </Table.Cell>
              <Table.Cell>{completedCell(info, status.timestamp_start)}</Table.Cell>
              <Table.Cell>
                <StepIcon info={info} />
              </Table.Cell>
            </Table.Row>
          ))}
        </Table.Body>
      </Table.Root>
    </SectionCard>
  );
}

function EnvoyLogsCard({ log }: { log: string }) {
  return (
    <SectionCard scroll title="Envoy Logs">
      <pre style={{ margin: 0, whiteSpace: 'pre-wrap' }}>{log || 'No logs recorded'}</pre>
    </SectionCard>
  );
}
