import { ActionIcon, Group, SimpleGrid, Text, Tooltip, UnstyledButton } from '@mantine/core';
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
      <Group gap="xs" wrap="nowrap" mb={4}>
        <Text fw={500} flex={1}>
          Test Library
        </Text>
        <ModalButton
          title="Filter Compliance Classes"
          size="lg"
          trigger={(open) => (
            <ActionIcon
              variant="outline"
              size="lg"
              onClick={open}
              aria-label="Filter compliance classes"
            >
              <IconAdjustmentsHorizontal size={18} />
            </ActionIcon>
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
      </Group>

      <Text size="sm" c="dimmed" mb={4}>
        {filterSummaryText(enabledNames, allClassNames.length)}
      </Text>

      <div>
        {categories.map(([category, tests]) => (
          <details key={category} open className={accordionClasses.item}>
            <summary className={accordionClasses.control}>{category}</summary>
            <SimpleGrid cols={2} spacing={0} verticalSpacing={0}>
              {tests.map((t) => {
                  const queued = queuedIds.has(t.id);
                  return (
                    <Tooltip
                      key={t.id}
                      label={t.description}
                      position="right"
                      withArrow
                      openDelay={400}
                    >
                      <UnstyledButton
                        onClick={() => onToggle(t)}
                        p="4px 8px"
                        w="100%"
                        bg={queued ? 'blue.1' : undefined}
                        fw={queued ? 500 : undefined}
                        style={{
                          border: '1px solid var(--mantine-color-gray-3)',
                          display: 'block',
                        }}
                      >
                        <Group gap={5} wrap="nowrap">
                          <Text component="span" c={queued ? 'blue' : 'dimmed'}>
                            {queued ? '✓' : '☐'}
                          </Text>
                          <Text span ff="monospace" size="sm" truncate>
                            {t.id}
                          </Text>
                        </Group>
                      </UnstyledButton>
                    </Tooltip>
                  );
                })}
            </SimpleGrid>
          </details>
        ))}
      </div>
    </>
  );
}
