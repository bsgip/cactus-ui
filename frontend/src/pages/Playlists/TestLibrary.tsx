import { ActionIcon, Accordion, Box, Group, SimpleGrid, Text, Tooltip } from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import { IconAdjustmentsHorizontal } from '@tabler/icons-react';
import { useState } from 'react';
import type { ComplianceClass, PlaylistTest } from '../../api/types';
import accordionClasses from '../../components/categoryAccordion.module.css';
import { ComplianceFilterModal } from '../Runs/ComplianceFilterModal';

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

// Port of the playlists.html left panel: compliance class filter and the per-category test
// grid. Clicking a test toggles its membership in the playlist queue.
export function TestLibrary({ testsByCategory, classes, queuedIds, onToggle }: TestLibraryProps) {
  const [filterOpened, { open: openFilter, close: closeFilter }] = useDisclosure(false);
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
        <Text fw={500} style={{ flex: 1 }}>
          Test Library
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

      <Text size="sm" c="dimmed" mb={4}>
        {filterSummaryText(enabledNames, allClassNames.length)}
      </Text>

      <ComplianceFilterModal
        opened={filterOpened}
        onClose={closeFilter}
        classes={classes}
        enabled={enabledClasses}
        onChange={setEnabledClasses}
      />

      <Accordion
        multiple
        defaultValue={Object.keys(testsByCategory)}
        classNames={{ control: accordionClasses.control }}
      >
        {categories.map(([category, tests]) => (
          <Accordion.Item key={category} value={category}>
            <Accordion.Control>{category}</Accordion.Control>
            <Accordion.Panel p={0}>
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
                      <Box
                        role="button"
                        tabIndex={0}
                        onClick={() => onToggle(t)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            e.preventDefault();
                            onToggle(t);
                          }
                        }}
                        p="4px 8px"
                        style={{
                          cursor: 'pointer',
                          border: '1px solid var(--mantine-color-gray-3)',
                          fontSize: '0.85rem',
                          display: 'flex',
                          alignItems: 'center',
                          gap: 5,
                          backgroundColor: queued ? 'var(--mantine-color-blue-1)' : undefined,
                          fontWeight: queued ? 500 : undefined,
                          overflow: 'hidden',
                          whiteSpace: 'nowrap',
                          textOverflow: 'ellipsis',
                        }}
                      >
                        <Text component="span" c={queued ? 'blue' : 'dimmed'}>
                          {queued ? '✓' : '☐'}
                        </Text>
                        <Text span ff="monospace">
                          {t.id}
                        </Text>
                      </Box>
                    </Tooltip>
                  );
                })}
              </SimpleGrid>
            </Accordion.Panel>
          </Accordion.Item>
        ))}
      </Accordion>
    </>
  );
}
