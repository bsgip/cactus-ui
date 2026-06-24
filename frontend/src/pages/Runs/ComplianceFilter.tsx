import { Button, Checkbox, Group, Stack, Text } from '@mantine/core';
import type { ComplianceClass } from '../../api/types';

interface ComplianceFilterProps {
  classes: ComplianceClass[];
  enabled: Set<string>;
  onChange: (enabled: Set<string>) => void;
  close: () => void;
}

// Compliance classes are defined in TS 5573:2025 (Table 12.5).
export function ComplianceFilter({ classes, enabled, onChange, close }: ComplianceFilterProps) {
  const allEnabled = enabled.size === classes.length;

  const toggle = (name: string, checked: boolean) => {
    const next = new Set(enabled);
    if (checked) {
      next.add(name);
    } else {
      next.delete(name);
    }
    onChange(next);
  };

  return (
    <>
      <Text mb="sm">The following compliance classes are defined in TS 5573:2025 (Table 12.5)</Text>
      <Stack gap="xs">
        {classes.map((c) => (
          <Checkbox
            key={c.name}
            checked={enabled.has(c.name)}
            onChange={(event) => toggle(c.name, event.currentTarget.checked)}
            label={
              <>
                <strong>({c.name})</strong> {c.description}
              </>
            }
          />
        ))}
      </Stack>
      <Group justify="flex-end" mt="md">
        <Button
          variant="outline"
          onClick={() => onChange(allEnabled ? new Set() : new Set(classes.map((c) => c.name)))}
        >
          {allEnabled ? 'Select NONE' : 'Select ALL'}
        </Button>
        <Button onClick={close}>Close</Button>
      </Group>
    </>
  );
}
