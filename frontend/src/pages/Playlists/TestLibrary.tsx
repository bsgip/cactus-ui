import { Flex, Grid, IconButton, Text, Tooltip } from '@radix-ui/themes';
import { IconAdjustmentsHorizontal } from '@tabler/icons-react';
import { useState } from 'react';
import type { ComplianceClass, PlaylistTest } from '../../api/types';
import accordionClasses from '../../components/categoryAccordion.module.css';
import { ModalButton } from '../../components/ModalButton';
import { ComplianceFilter } from '../Runs/ComplianceFilter';

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
    <>
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
          <details key={category} open className={accordionClasses.item}>
            <summary className={accordionClasses.control}>{category}</summary>
            <Grid columns="2" gap="0">
              {tests.map((t) => {
                const queued = queuedIds.has(t.id);
                return (
                  <Tooltip key={t.id} content={t.description} side="right" delayDuration={400}>
                    <button
                      type="button"
                      onClick={() => onToggle(t)}
                      style={{
                        display: 'block',
                        width: '100%',
                        padding: '4px 8px',
                        textAlign: 'left',
                        cursor: 'pointer',
                        border: '1px solid var(--gray-5)',
                        background: queued ? 'var(--blue-3)' : 'transparent',
                        fontWeight: queued ? 500 : undefined,
                      }}
                    >
                      <Flex gap="1" align="center">
                        <Text as="span" color={queued ? 'blue' : 'gray'}>
                          {queued ? '✓' : '☐'}
                        </Text>
                        <Text
                          as="span"
                          size="2"
                          truncate
                          style={{ fontFamily: 'var(--code-font-family)' }}
                        >
                          {t.id}
                        </Text>
                      </Flex>
                    </button>
                  </Tooltip>
                );
              })}
            </Grid>
          </details>
        ))}
      </div>
    </>
  );
}
