import {
  Flex,
  Heading,
  TextField,
  Link,
} from '@radix-ui/themes';


import { FormState } from '../utils/complianceRequestForm';
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
      <FieldRow label="Series Name" help="The designation used in product catalogues and labelling to identify all related models in this series.">
        <TextField.Root
          value={form.der_series}
          onChange={(e) => update({ der_series: e.target.value })}
          disabled={readOnly}
        />
      </FieldRow>
      <Heading as="h4" size="3">
        Models under test
      </Heading>
      <FieldRow label="CEC-listed Models" help={<>List of models under test with CEC-listing. Only include models here that are included on the <Link href="#">CEC Approved Inverters List</Link>.</>}>
        <TextField.Root
          value={form.der_cec_listed_models}
          onChange={(e) => update({ der_cec_listed_models: e.target.value })}
          disabled={readOnly}
        />
      </FieldRow>
      <FieldRow label="Unlisted Models" help="List of models under test that are not CEC-listing.">
        <TextField.Root
          value={form.der_unlisted_models}
          onChange={(e) => update({ der_unlisted_models: e.target.value })}
          disabled={readOnly}
        />
      </FieldRow>
      <FieldRow label="White-labelled Models" help="If the DER is a white-labelled product marketed under different brand names, provide relevant information and list the white-labelled products.">
        <TextField.Root
          value={form.der_white_labelled_models}
          onChange={(e) => update({ der_white_labelled_models: e.target.value })}
          disabled={readOnly}
        />
      </FieldRow>
    </Flex>
  );
}

export default DerDetailsStep;
