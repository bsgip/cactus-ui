import { Flex, Grid, IconButton, Text, Tooltip } from '@radix-ui/themes';
import { IconAdjustmentsHorizontal, IconCheck } from '@tabler/icons-react';
import { useState, type ReactNode } from 'react';
import type { ComplianceClass } from '../api/types';
import { CategoryAccordion } from './CategoryAccordion';
import { ComplianceFilter } from './ComplianceFilter';
import { InfoPopover } from './InfoPopover';
import { ModalButton } from './ModalButton';
import styles from './complianceLibrary.module.css';

export interface LibraryItem {
  id: string;
  description?: string;
  classes: string[];
  badge?: ReactNode;
}

interface ComplianceLibraryProps {
  title: ReactNode;
  itemsByCategory: Record<string, LibraryItem[]>;
  complianceClasses: ComplianceClass[];
  selectedIds: Set<string>;
  onSelect: (id: string) => void;
  // Playlists toggles membership (checkbox); Runs picks one procedure (no checkbox).
  showCheckbox?: boolean;
  columns?: '1' | '2';
  // Rendered above the filter header — used by Runs for the "Active Runs" entry.
  topContent?: ReactNode;
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

// Compliance-class filter plus per-category accordions of selectable cells. Shared by the Runs
// procedure list and the Playlists test library so the two stay visually consistent; behaviour
// differs only via showCheckbox (single-pick vs toggle) and the optional per-item badge.
export function ComplianceLibrary({
  title,
  itemsByCategory,
  complianceClasses,
  selectedIds,
  onSelect,
  showCheckbox = false,
  columns = '1',
  topContent,
}: ComplianceLibraryProps) {
  const [enabledClasses, setEnabledClasses] = useState<Set<string>>(
    () => new Set(complianceClasses.map((c) => c.name))
  );

  const allClassNames = complianceClasses.map((c) => c.name);
  const enabledNames = allClassNames.filter((n) => enabledClasses.has(n));
  const allEnabled = enabledClasses.size === allClassNames.length;

  // Classless items are always shown; otherwise an item needs at least one enabled class.
  const isVisible = (item: LibraryItem): boolean =>
    allEnabled || item.classes.length === 0 || item.classes.some((c) => enabledClasses.has(c));

  const categories = Object.entries(itemsByCategory)
    .map(([category, items]) => [category, items.filter(isVisible)] as const)
    .filter(([, items]) => items.length > 0);

  return (
    <div>
      {topContent}

      <Flex gap="2" align="center" mb="1">
        <Text weight="medium" style={{ flex: 1 }}>
          {title}
        </Text>
        <ModalButton
          title="Filter Compliance Classes"
          size="lg"
          trigger={(open) => (
            <IconButton
              variant="outline"
              color="blue"
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
              classes={complianceClasses}
              enabled={enabledClasses}
              onChange={setEnabledClasses}
              close={close}
            />
          )}
        </ModalButton>
      </Flex>

      <Text as="div" size="2" color="gray" mb="1">
        {filterSummaryText(enabledNames, allClassNames.length)}
      </Text>

      <div>
        {categories.map(([category, items]) => (
          <CategoryAccordion
            key={category}
            title={
              category.toLowerCase() === 'provisional' ? (
                <Flex gap="1" align="center">
                  <span>{category}</span>
                  <span onClick={(e) => e.preventDefault()}>
                    <InfoPopover title="Provisional tests" label="What are provisional tests?">
                      Provisional tests aren&apos;t required for CSIP-Aus compliance. They&apos;re
                      drawn from real-world integration issues seen in the field, and we strongly
                      recommend running them to catch problems before deployment.
                    </InfoPopover>
                  </span>
                </Flex>
              ) : (
                category
              )
            }
            count={items.length}
          >
            <Grid columns={columns} gap="0">
              {items.map((item) => {
                const selected = selectedIds.has(item.id);
                const cell = (
                  <button
                    type="button"
                    aria-pressed={selected}
                    onClick={() => onSelect(item.id)}
                    className={`${styles.cell} ${selected ? styles.cellSelected : ''}`}
                  >
                    <Flex gap="2" align="center" justify="between">
                      <Flex gap="2" align="center" style={{ minWidth: 0 }}>
                        {showCheckbox && (
                          <span className={`${styles.box} ${selected ? styles.boxChecked : ''}`}>
                            {selected && <IconCheck size={11} stroke={3} />}
                          </span>
                        )}
                        <Text as="span" size="2" truncate weight={selected ? 'medium' : 'regular'}>
                          {item.id}
                        </Text>
                      </Flex>
                      {item.badge}
                    </Flex>
                  </button>
                );
                return item.description ? (
                  <Tooltip
                    key={item.id}
                    content={item.description}
                    side="right"
                    delayDuration={400}
                  >
                    {cell}
                  </Tooltip>
                ) : (
                  <div key={item.id}>{cell}</div>
                );
              })}
            </Grid>
          </CategoryAccordion>
        ))}
      </div>
    </div>
  );
}
