import {
  Flex,
  Heading,
  Select,
  TextArea,
  TextField,
} from '@radix-ui/themes';

import { FormState } from '../utils/complianceRequestForm';
import FieldRow from '../components/FieldRow';

function SoftwareClientDetailsStep({
  form,
  readOnly,
  update,
}: {
  form: FormState;
  readOnly: boolean;
  update: (patch: Partial<FormState>) => void;
}) {
  return (
    <Flex direction="column" gap="4" pt="4">
      <Heading as="h3" size="4">
        Software Client
      </Heading>
      <FieldRow
        label="Type"
        help="Direct - the DER connects with its own client representing a single site. Proxy (Aggregator) - DER(s) connect via a communications aggregator that may represent many sites."
      >
        <Select.Root
          value={form.software_client_type}
          onValueChange={(v) => update({ software_client_type: v })}
          disabled={readOnly}
        >
          <Select.Trigger />
          <Select.Content>
            <Select.Item value="direct">Direct</Select.Item>
            <Select.Item value="proxy">Proxy (Aggregator)</Select.Item>
          </Select.Content>
        </Select.Root>
      </FieldRow>
      <FieldRow
        label="Provider(s)"
        help="The software client may be provided by an OEM or third-party."
      >
        <TextField.Root
          value={form.software_client_providers}
          onChange={(e) => update({ software_client_providers: e.target.value })}
          disabled={readOnly}
        />
      </FieldRow>
      <FieldRow
        label="Version(s)"
        help="The full name and version(s) of all software clients, plus any intermediate cloud server(s) or platform(s)."
      >
        <TextField.Root
          value={form.software_client_versions}
          onChange={(e) => update({ software_client_versions: e.target.value })}
          disabled={readOnly}
        />
      </FieldRow>
      <Heading as="h3" size="4">
        On-site Hardware
      </Heading>
      <FieldRow
        label="Details"
        help="Makes and models of any on-site gateway, control, EMS device or external accessories that are part of the software client implementation."
      >
        <TextArea
          rows={3}
          value={form.onsite_hardware_details}
          onChange={(e) => update({ onsite_hardware_details: e.target.value })}
          disabled={readOnly}
        />
      </FieldRow>
    </Flex>
  );
}

export default SoftwareClientDetailsStep;
