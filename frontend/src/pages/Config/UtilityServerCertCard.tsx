import { Button, Flex, Text } from '@radix-ui/themes';
import { IconDownload } from '@tabler/icons-react';
import { InfoPopover } from '../../components/InfoPopover';
import { SectionCard } from '../../components/SectionCard';

// Download bundle for the *reverse* mTLS direction: what an aggregator's webhook needs in order to
// trust the utility server (envoy) when it POSTs notifications out. Served as a ZIP by the
// orchestrator's GET /certificate/authority (SERCA trust anchor + the utility-server chain).
export function UtilityServerCertCard() {
  return (
    <SectionCard
      title={
        <Flex align="center" gap="1">
          <Text weight="bold" size="3">
            Utility Server Certificates
          </Text>
          <InfoPopover title="Utility Server Certificates">
            When the utility server (envoy) sends subscription notifications to your webhook it
            connects as a TLS client and presents its own certificate. To accept those connections
            your webhook must trust them. This bundle contains:
            <ul style={{ margin: '0.5rem 0 0', paddingLeft: '1.1rem' }}>
              <li>
                <strong>serca.pem</strong> — the root trust anchor; install it in your webhook&apos;s
                trust store.
              </li>
              <li>
                <strong>utility-server-fullchain.pem</strong> — the utility server&apos;s identity
                chain (excluding the root).
              </li>
            </ul>
          </InfoPopover>
        </Flex>
      }
    >
      <Text as="p" mb="3" color="gray">
        Download the trust anchor and utility-server chain your aggregator webhook needs in order to
        accept outgoing subscription notifications over mutual TLS.
      </Text>
      <Button asChild variant="outline">
        <a href="/config/ca_cert">
          <IconDownload size={14} />
          Download Utility Server Certificates
        </a>
      </Button>
    </SectionCard>
  );
}
