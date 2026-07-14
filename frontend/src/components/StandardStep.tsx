import {
  Callout,
  Flex,
  Link,
  Select,
  Text,
  TextField,
} from '@radix-ui/themes';
import { IconAlertTriangle } from '@tabler/icons-react';

import { Mode, FormState } from '../utils/complianceRequestWizard';

interface StandardStepProps {
  form: FormState;
  mode: Mode;
  readOnly: boolean;
  versions: string[];
  update: (patch: Partial<FormState>) => void;
};

function StandardStep({
  form,
  mode,
  readOnly,
  versions,
  update,
}: StandardStepProps) {
  return (
    <Flex direction="column" gap="4" pt="4">
      {mode === 'new' && (
        <Callout.Root color="yellow">
          <Callout.Icon>
            <IconAlertTriangle size={16} />
          </Callout.Icon>
          <Callout.Text>
            Witness testing must be completed before a compliance request can be submitted. If you
            are yet to complete witness testing, please contact{' '}
            <Link href="mailto:support@bsgip.com">support@bsgip.com</Link> to arrange a date.
          </Callout.Text>
        </Callout.Root>
      )}
      <label>
        <Text as="div" size="2" weight="bold" mb="1">
          Compliance Standard
        </Text>
        <Select.Root
          value={form.csip_aus_version}
          onValueChange={(v) => update({ csip_aus_version: v })}
          disabled={readOnly}
        >
          <Select.Trigger placeholder="Select a version" />
          <Select.Content>
            {versions.map((v) => (
              <Select.Item key={v} value={v}>
                CSIP-Aus {v}
              </Select.Item>
            ))}
          </Select.Content>
        </Select.Root>
        <Text as="div" size="1" color="gray" mt="1">
          A compliance request can only be made against one compliance standard at a time.
        </Text>
      </label>
      <label>
        <Text as="div" size="2" weight="bold" mb="1">
          Witness Testing Date
        </Text>
        <TextField.Root
          type="date"
          value={form.witnessed_at}
          onChange={(e) => update({ witnessed_at: e.target.value })}
          disabled={readOnly}
        />
        <Text as="div" size="1" color="gray" mt="1">
          The date when in-person witness testing was performed.
        </Text>
      </label>
    </Flex>
  );
}

export default StandardStep;
