import { Flex, Grid, IconButton, Text, Tooltip } from '@radix-ui/themes';
import { IconAdjustmentsHorizontal, IconCheck } from '@tabler/icons-react';
import { useState } from 'react';
import type { ComplianceClass, PlaylistTest } from '../../api/types';
import { CategoryAccordion } from '../../components/CategoryAccordion';
import { ModalButton } from '../../components/ModalButton';
import { ComplianceFilter } from '../Runs/ComplianceFilter';
import cellClasses from './testLibrary.module.css';

interface TestLibraryProps {
  testsByCategory: Record<string, PlaylistTest[]>;
  classes: ComplianceClass[];
  queuedIds: Set<string>;
  onToggle: (test: PlaylistTest) => void;
}

function filterSummaryText(enabledNames: string[], totalClasses: number): string {
  if (enabledNames.length === totalClasses) {
    return 'Showing ALL compliance classes';
  }
  if (enabledNames.length === 0) {
    return 'Showing NO compliance classes';
  }
  if (enabledNames.length <= 4) {
    return `Showing ${enabledNames.join(', ')}`;
  }
  return `Showing ${enabledNames.length} compliance classes`;
}

// Compliance-class filter plus the per-category test grid; clicking a test toggles its
// membership in the playlist queue.
export function TestLibrary({ testsByCategory, classes, queuedIds, onToggle }: TestLibraryProps) {
  const [enabledClasses, setEnabledClasses] = useState<Set<string>>(
    () => new Set(classes.map((c) => c.name))
  );

  const allClassNames = classes.map((c) => c.name);
  const enabledNames = allClassNames.filter((n) => enabledClasses.has(n));
  const allEnabled = enabledClasses.size === allClassNames.length;

  const isVisible = (t: PlaylistTest): boolean => {
    // Tests with no class membership are always shown.
    if (!allEnabled && t.classes.length > 0 && !t.classes.some((c) => enabledClasses.has(c))) {
      return false;
    }
    return true;
  };

  const categories = Object.entries(testsByCategory)
    .map(([category, tests]) => [category, tests.filter(isVisible)] as const)
    .filter(([, tests]) => tests.length > 0);

  return (
    <div>
      <Flex gap="2" align="center" mb="1">
        <Text weight="medium" style={{ flex: 1 }}>
          Test Library
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
              classes={classes}
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
        {categories.map(([category, tests]) => (
          <CategoryAccordion key={category} title={category} count={tests.length}>
            <Grid columns="2" gap="0">
              {tests.map((t) => {
                const queued = queuedIds.has(t.id);
                return (
                  <Tooltip key={t.id} content={t.description} side="right" delayDuration={400}>
                    <button
                      type="button"
                      aria-pressed={queued}
                      onClick={() => onToggle(t)}
                      className={`${cellClasses.cell} ${queued ? cellClasses.cellSelected : ''}`}
                    >
                      <Flex gap="2" align="center">
                        <span
                          className={`${cellClasses.box} ${queued ? cellClasses.boxChecked : ''}`}
                        >
                          {queued && <IconCheck size={11} stroke={3} />}
                        </span>
                        <Text as="span" size="2" truncate weight={queued ? 'medium' : 'regular'}>
                          {t.id}
                        </Text>
                      </Flex>
                    </button>
                  </Tooltip>
                );
              })}
            </Grid>
          </CategoryAccordion>
        ))}
      </div>
    </div>
  );
}
