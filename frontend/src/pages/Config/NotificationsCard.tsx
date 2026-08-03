import { Button, Flex, Text } from '@radix-ui/themes';
import { updateDomain } from '../../api/config';
import { SaveField } from '../../components/SaveField';
import { Section } from '../../components/Section';
import { IconDownload } from '@tabler/icons-react';
import { InfoPopover } from '../../components/InfoPopover';

// Account-wide settings that sit above run groups: the organisation identity baked into every
// issued certificate (PEN, notification domain) and the utility-server trust bundle an aggregator
// webhook needs to accept notifications. Grouped here so "set up once per organisation" actions
// are separated from the per-device run group workflow below.
export function NotificationsCard({
  domain,
  setError,
}: {
  domain: string;
  setError: (msg: string | null) => void;
}) {
  return (
    <Section title="SUBSCRIPTION-BASED NOTIFICATIONS">


        <Text as="p" mb="3">
          Notification settings control how the utility server delivers subscription notifications to you. For aggregators that subscribe to resources, the utility server delivers notifications
          to your webhook over mutual TLS.
        </Text>

        <Text as="p" mb="6">
          Register your webhook&apos;s domain here, and install
          the utility server certificates in your webhook&apos;s trust store.
        </Text>

        <SaveField
          label="Notification Domain — required for aggregator certificates"
          infoTitle="Notification Domain"
          info={
            <>
              The fully-qualified domain of your webhook endpoint. The utility server (envoy) uses
              it to send subscription notifications back to you over mutual TLS, so it is baked into
              the SAN of any <strong>aggregator</strong> certificate you generate and is checked
              when notifications are delivered. Device certificates do not use it. All subscription
              notification URIs must use this registered domain or they will be rejected.
            </>
          }
          savedValue={domain}
          placeholder="e.g. my.example.com"
          emptyHint="Not set — aggregator certificates cannot be generated until a domain is registered."
          saveLabel="Save Domain"
          confirmTitle="Update the notification domain?"
          confirmBody="Your certificates must whitelist the subscription domain — changing it means you will need to manually regenerate your existing aggregator certificates before notifications can be delivered."
          save={(value) => updateDomain(value)}
          setError={setError}
        />

        <UtilityServerCertDownloader />
    </Section>
  );
}


function UtilityServerCertDownloader() {
  return (
        <Flex direction="column" gap="2">
          <Flex align="center" gap="1">
            <Text weight="bold" size="2">
              Utility Server Certificates
            </Text>
            <InfoPopover title="Utility Server Certificates">
              When the utility server (envoy) sends subscription notifications to your webhook it
              connects as a TLS client and presents its own certificate. To accept those connections
              your webhook must trust them. This bundle contains:
              <ul style={{ margin: '0.5rem 0 0', paddingLeft: '1.1rem' }}>
                <li>
                  <strong>serca.pem</strong> — the root trust anchor; install it in your
                  webhook&apos;s trust store.
                </li>
                <li>
                  <strong>utility-server-fullchain.pem</strong> — the utility server&apos;s identity
                  chain (excluding the root).
                </li>
              </ul>
            </InfoPopover>
          </Flex>
          <Flex>
            <Button asChild variant="outline">
              <a href="/config/ca_cert">
                <IconDownload size={14} />
                Download Utility Server Certificates
              </a>
            </Button>
          </Flex>
        </Flex>
  );
}
