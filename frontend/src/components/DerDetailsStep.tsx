import {
  Flex,
  Heading,
  TextArea,
  TextField,
} from '@radix-ui/themes';


import { FormState } from '../utils/complianceRequestWizard';
import FieldRow from '../components/FieldRow';

function DerDetailsStep({
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
        DER
      </Heading>
      <FieldRow label="Brand">
        <TextField.Root
          value={form.der_brand}
          onChange={(e) => update({ der_brand: e.target.value })}
          disabled={readOnly}
        />
      </FieldRow>
      <FieldRow label="OEM">
        <TextField.Root
          value={form.der_oem}
          onChange={(e) => update({ der_oem: e.target.value })}
          disabled={readOnly}
        />
      </FieldRow>
      <FieldRow label="Series" help="The series or product line the DER belongs to.">
        <TextField.Root
          value={form.der_series}
          onChange={(e) => update({ der_series: e.target.value })}
          disabled={readOnly}
        />
      </FieldRow>
      <FieldRow
        label="Representative Models"
        help="Models in the DER series. Models must use the same software and hardware configuration; they may differ in rated power or phases."
      >
        <TextArea
          rows={3}
          value={form.der_representative_models}
          onChange={(e) => update({ der_representative_models: e.target.value })}
          disabled={readOnly}
        />
      </FieldRow>
    </Flex>
  );
}

export default DerDetailsStep;
