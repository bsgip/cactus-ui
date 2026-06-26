import { Badge, Text } from '@radix-ui/themes';
import type { ProcedureSummariesResponse, TestProcedureRunSummary } from '../../api/types';
import { ComplianceLibrary, type LibraryItem } from '../../components/ComplianceLibrary';
import styles from '../../components/complianceLibrary.module.css';
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

export function ProcedureList({ summaries, selection, onSelect }: ProcedureListProps) {
  const itemsByCategory: Record<string, LibraryItem[]> = {};
  const descriptions = new Map<string, string>();
  for (const gp of summaries.grouped_procedures) {
    itemsByCategory[gp.category] = gp.summaries.map((p) => {
      descriptions.set(p.test_procedure_id, p.description);
      return {
        id: p.test_procedure_id,
        description: p.description,
        classes: p.classes ?? [],
        badge: p.run_count > 0 ? <Badge color={badgeColor(p)}>{p.run_count}</Badge> : undefined,
      };
    });
  }

  const activeSelected = selection.kind === 'active';

  return (
    <ComplianceLibrary
      title="Procedures"
      itemsByCategory={itemsByCategory}
      complianceClasses={summaries.classes}
      selectedIds={selection.kind === 'procedure' ? new Set([selection.id]) : new Set()}
      onSelect={(id) =>
        onSelect({ kind: 'procedure', id, description: descriptions.get(id) ?? '' })
      }
      topContent={
        <button
          type="button"
          aria-pressed={activeSelected}
          onClick={() => onSelect({ kind: 'active' })}
          className={`${styles.cell} ${activeSelected ? styles.cellSelected : ''}`}
          style={{ marginBottom: 8 }}
        >
          <Text as="span" size="2" weight={activeSelected ? 'medium' : 'regular'}>
            Active Runs
          </Text>
        </button>
      }
    />
  );
}
