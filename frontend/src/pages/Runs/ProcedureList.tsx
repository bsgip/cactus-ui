import { Badge, Button, Flex, IconButton, Text } from '@radix-ui/themes';
import { useState } from 'react';
import { IconAdjustmentsHorizontal } from '@tabler/icons-react';
import type { ProcedureSummariesResponse, TestProcedureRunSummary } from '../../api/types';
import accordionClasses from '../../components/categoryAccordion.module.css';
import { ModalButton } from '../../components/ModalButton';
import { ComplianceFilter } from './ComplianceFilter';
import type { RunsSelection } from './RunsPage';

interface ProcedureListProps {
  summaries: ProcedureSummariesResponse;
  selection: RunsSelection;
  onSelect: (selection: RunsSelection) => void;
}

function badgeColor(summary: TestProcedureRunSummary): 'green' | 'red' | 'gray' {
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

export function ProcedureList({ summaries, selection, onSelect }: ProcedureListProps) {
  const [enabledClasses, setEnabledClasses] = useState<Set<string>>(
    () => new Set(summaries.classes.map((c) => c.name))
  );

  const enabledNames = summaries.classes.map((c) => c.name).filter((n) => enabledClasses.has(n));
  const visibleGroups = summaries.grouped_procedures.filter((gp) =>
    matchesFilter(summaries.classes_by_category[gp.slug], enabledClasses)
  );

  return (
    <Flex direction="column" gap="2">
      <Button
        variant={selection.kind === 'active' ? 'solid' : 'soft'}
        color={selection.kind === 'active' ? undefined : 'gray'}
        onClick={() => onSelect({ kind: 'active' })}
        style={{ justifyContent: 'flex-start', width: '100%' }}
      >
        Active Runs
      </Button>

      <Flex gap="2" align="center">
        <Text size="2" style={{ flex: 1 }}>
          {filterSummaryText(enabledNames, summaries.classes.length)}
        </Text>
        <ModalButton
          title="Filter Compliance Classes"
          size="lg"
          trigger={(open) => (
            <IconButton
              variant="outline"
              size="2"
              onClick={open}
              aria-label="Filter compliance classes"
            >
              <IconAdjustmentsHorizontal size={18} />
            </IconButton>
          )}
        >
          {(close) => (
            <ComplianceFilter
              classes={summaries.classes}
              enabled={enabledClasses}
              onChange={setEnabledClasses}
              close={close}
            />
          )}
        </ModalButton>
      </Flex>

      <div>
        {visibleGroups.map((gp) => (
          <details key={gp.slug} open className={accordionClasses.item}>
            <summary className={accordionClasses.control}>{gp.category}</summary>
            <Flex direction="column" gap="1" p="1">
              {gp.summaries
                .filter((p) =>
                  matchesFilter(summaries.classes_by_test[p.test_procedure_id], enabledClasses)
                )
                .map((p) => {
                  const isActive =
                    selection.kind === 'procedure' && selection.id === p.test_procedure_id;
                  return (
                    <Button
                      key={p.test_procedure_id}
                      variant={isActive ? 'solid' : 'soft'}
                      color={isActive ? undefined : 'gray'}
                      onClick={() =>
                        onSelect({
                          kind: 'procedure',
                          id: p.test_procedure_id,
                          description: p.description,
                        })
                      }
                      style={{ justifyContent: 'space-between', width: '100%' }}
                    >
                      <span>{p.test_procedure_id}</span>
                      {p.run_count > 0 && <Badge color={badgeColor(p)}>{p.run_count}</Badge>}
                    </Button>
                  );
                })}
            </Flex>
          </details>
        ))}
      </div>
    </Flex>
  );
}
