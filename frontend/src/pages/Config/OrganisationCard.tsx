import { Link, Text } from '@radix-ui/themes';
import { updatePen } from '../../api/config';
import { SaveField } from '../../components/SaveField';
import { Section } from '../../components/Section';

// Account-wide settings that sit above run groups: the organisation identity baked into every
// issued certificate (PEN, notification domain) and the utility-server trust bundle an aggregator
// webhook needs to accept notifications. Grouped here so "set up once per organisation" actions
// are separated from the per-device run group workflow below.
export function OrganisationCard({
  pen,
  setError,
}: {
  pen: number | null;
  setError: (msg: string | null) => void;
}) {
  return (
    <Section title="IDENTITY">
      <Text as="p" mb="3">
        Your identity is set through a Private Enterprise Number (PEN).
      </Text>

      <Text as="p" mb="6">
        The PEN is embedded in every device and aggregator certificate you
        generate (see the <i>Run Groups & Certificates</i> section below).
      </Text>

      <SaveField
        label="Private Enterprise Number (PEN)"
        infoTitle="Private Enterprise Number (PEN)"
        info={
          <>
            A PEN is a numeric identifier IANA assigns to an organisation. CSIP-Aus requires
            clients to encode a PEN in various requests, and CACTUS embeds it in every issued
            certificate (as the hardware-module <em>hwType</em> OID). Leave blank to use the
            reserved value <strong>0</strong>. Obtain one for free from{' '}
            <Link href="https://www.iana.org/assignments/enterprise-numbers/" target="_blank">
              IANA
            </Link>
            .
          </>
        }
        savedValue={pen != null ? String(pen) : ''}
        placeholder="e.g. 123456"
        emptyHint="Not set — certificates will use the reserved value 0."
        saveLabel="Save PEN"
        confirmTitle="Update your PEN?"
        confirmBody="Your PEN is embedded in every certificate you generate. Existing certificates keep the old PEN — you will need to manually regenerate them for the change to take effect."
        inputProps={{ type: 'number', min: 1, max: 4294967295 }}
        save={(value) => updatePen(Number(value))}
        setError={setError}
        mb="0"
      />

    </Section>
  );
}

