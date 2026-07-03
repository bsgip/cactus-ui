import type { ComplianceClass, PlaylistTest } from '../../api/types';
import { ComplianceLibrary, type LibraryItem } from '../../components/ComplianceLibrary';

interface TestLibraryProps {
  testsByCategory: Record<string, PlaylistTest[]>;
  classes: ComplianceClass[];
  queuedIds: Set<string>;
  onToggle: (test: PlaylistTest) => void;
}

// Compliance-class filter plus the per-category test grid; clicking a test toggles its
// membership in the playlist queue.
export function TestLibrary({ testsByCategory, classes, queuedIds, onToggle }: TestLibraryProps) {
  const tests = new Map<string, PlaylistTest>();
  const itemsByCategory: Record<string, LibraryItem[]> = {};
  for (const [category, categoryTests] of Object.entries(testsByCategory)) {
    itemsByCategory[category] = categoryTests.map((t) => {
      tests.set(t.id, t);
      return { id: t.id, description: t.description, classes: t.classes };
    });
  }

  return (
    <ComplianceLibrary
      title="Test Library"
      itemsByCategory={itemsByCategory}
      complianceClasses={classes}
      selectedIds={queuedIds}
      onSelect={(id) => {
        const test = tests.get(id);
        if (test) {
          onToggle(test);
        }
      }}
      showCheckbox
      columns="2"
    />
  );
}
