import { Accordion, ActionIcon, Badge, Group, NavLink, Stack, Text } from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import { useState } from 'react';
import { IconAdjustmentsHorizontal } from '@tabler/icons-react';
import type { ProcedureSummariesResponse, TestProcedureRunSummary } from '../../api/types';
import accordionClasses from '../../components/categoryAccordion.module.css';
import { ComplianceFilterModal } from './ComplianceFilterModal';
import type { RunsSelection } from './RunsPage';

interface ProcedureListProps {
  summaries: ProcedureSummariesResponse;
  selection: RunsSelection;
  onSelect: (selection: RunsSelection) => void;
}

function badgeColor(summary: TestProcedureRunSummary): string {
  if (summary.latest_all_criteria_met === true) {
    return 'green';
  }
  if (summary.latest_all_criteria_met === false) {
    return 'red';
  }
  return 'gray';
}

function matchesFilter(classes: string[] | undefined, enabled: Set<string>): boolean {
  return (classes ?? []).some((c) => enabled.has(c));
}

function filterSummaryText(enabledNames: string[], totalClasses: number): string {
  if (enabledNames.length === totalClasses) {
    return 'Showing ALL compliance classes';
  }
  if (enabledNames.length === 0) {
    return 'Showing NO compliance classes';
  }
  if (enabledNames.length < 5) {
    return `Showing ${enabledNames.join(', ')}`;
  }
  return `Showing ${enabledNames.length} compliance classes`;
}

// Port of the runs.html left column: Active Runs button, compliance class filter,
// and the per-category collapsible procedure list with run-count badges.
export function ProcedureList({ summaries, selection, onSelect }: ProcedureListProps) {
  const [filterOpened, { open: openFilter, close: closeFilter }] = useDisclosure(false);
  const [enabledClasses, setEnabledClasses] = useState<Set<string>>(
    () => new Set(summaries.classes.map((c) => c.name))
  );

  const enabledNames = summaries.classes.map((c) => c.name).filter((n) => enabledClasses.has(n));
  const visibleGroups = summaries.grouped_procedures.filter((gp) =>
    matchesFilter(summaries.classes_by_category[gp.slug], enabledClasses)
  );

  return (
    <Stack gap="xs">
      <NavLink
        component="button"
        label="Active Runs"
        active={selection.kind === 'active'}
        onClick={() => onSelect({ kind: 'active' })}
      />

      <Group gap="xs" wrap="nowrap">
        <Text size="sm" style={{ flex: 1 }}>
          {filterSummaryText(enabledNames, summaries.classes.length)}
        </Text>
        <ActionIcon
          variant="outline"
          size="lg"
          onClick={openFilter}
          aria-label="Filter compliance classes"
        >
          <IconAdjustmentsHorizontal size={18} />
        </ActionIcon>
      </Group>

      <ComplianceFilterModal
        opened={filterOpened}
        onClose={closeFilter}
        classes={summaries.classes}
        enabled={enabledClasses}
        onChange={setEnabledClasses}
      />

      <Accordion
        multiple
        defaultValue={summaries.grouped_procedures.map((gp) => gp.slug)}
        classNames={{ control: accordionClasses.control }}
      >
        {visibleGroups.map((gp) => (
          <Accordion.Item key={gp.slug} value={gp.slug}>
            <Accordion.Control>{gp.category}</Accordion.Control>
            <Accordion.Panel p={0}>
              {gp.summaries
                .filter((p) =>
                  matchesFilter(summaries.classes_by_test[p.test_procedure_id], enabledClasses)
                )
                .map((p) => (
                  <NavLink
                    key={p.test_procedure_id}
                    component="button"
                    label={p.test_procedure_id}
                    active={selection.kind === 'procedure' && selection.id === p.test_procedure_id}
                    mt={4}
                    mx={4}
                    style={{
                      border: '1px solid var(--mantine-color-gray-3)',
                      borderRadius: 'var(--mantine-radius-sm)',
                    }}
                    onClick={() =>
                      onSelect({
                        kind: 'procedure',
                        id: p.test_procedure_id,
                        description: p.description,
                      })
                    }
                    rightSection={
                      p.run_count > 0 ? (
                        <Badge color={badgeColor(p)}>{p.run_count}</Badge>
                      ) : undefined
                    }
                  />
                ))}
            </Accordion.Panel>
          </Accordion.Item>
        ))}
      </Accordion>
    </Stack>
  );
}
