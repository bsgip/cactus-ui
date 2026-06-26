import { Button, Checkbox, Flex, Text } from '@radix-ui/themes';
import type { ComplianceClass } from '../api/types';

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
      <Text as="p" mb="2">
        The following compliance classes are defined in TS 5573:2025 (Table 12.5)
      </Text>
      <Flex direction="column" gap="2">
        {classes.map((c) => (
          <Text as="label" size="2" key={c.name}>
            <Flex gap="2" align="center">
              <Checkbox
                checked={enabled.has(c.name)}
                onCheckedChange={(checked) => toggle(c.name, checked === true)}
              />
              <span>
                <strong>({c.name})</strong> {c.description}
              </span>
            </Flex>
          </Text>
        ))}
      </Flex>
      <Flex justify="end" gap="3" mt="3">
        <Button
          variant="outline"
          onClick={() => onChange(allEnabled ? new Set() : new Set(classes.map((c) => c.name)))}
        >
          {allEnabled ? 'Select NONE' : 'Select ALL'}
        </Button>
        <Button onClick={close}>Close</Button>
      </Flex>
    </>
  );
}
