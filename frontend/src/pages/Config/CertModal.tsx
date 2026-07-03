import { Button, Code, Flex, Text, Tooltip } from '@radix-ui/themes';
import { IconDownload, IconPlus, IconRecycle } from '@tabler/icons-react';
import type { RunGroupResponse } from '../../api/types';
import { InfoPopover } from '../../components/InfoPopover';
import { ModalButton } from '../../components/ModalButton';

export function CertModal({
  runGroup,
  hasDomain,
  onCertAction,
}: {
  runGroup: RunGroupResponse;
  hasDomain: boolean;
  onCertAction: (message: string) => void;
}) {
  const hasCert = !!(runGroup.certificate_id && runGroup.certificate_created_at);
  const certType = runGroup.is_device_cert ? 'Device' : 'Aggregator';
  const certDate = runGroup.certificate_created_at
    ? new Date(runGroup.certificate_created_at).toLocaleDateString('sv')
    : null;

  return (
    <ModalButton
      title={`Certificate for ${runGroup.name}`}
      size="lg"
      trigger={(open) => (
        <Button variant={hasCert ? 'outline' : 'solid'} onClick={open}>
          {hasCert ? <IconRecycle size={14} /> : <IconPlus size={14} />}
          {hasCert ? 'Manage Certificate' : 'Generate Certificate'}
        </Button>
      )}
    >
      {(close) => {
        const handleFormSubmit = () => {
          close();
          onCertAction('Certificate generated — your download should begin automatically.');
        };
        return (
          <>
            <Flex direction="column" gap="3">
              {hasCert ? (
                <Text>
                  The current <Code>{certType}</Code> certificate (ID{' '}
                  <Code>{runGroup.certificate_id}</Code>) was created <Code>{certDate}</Code>
                  <br />
                  <br />
                  <strong>Note:</strong> The replace buttons below generate and download a brand-new
                  certificate, and the current certificate stops working immediately — your device
                  or client must switch to the new one before its next test run.
                </Text>
              ) : (
                <Text>
                  There is <strong>no</strong> certificate on record for this run group. You will
                  need to create one in order to create test runs.
                </Text>
              )}

              <Flex align="center" gap="2">
                <Text size="2" weight="bold">
                  {hasCert ? 'Replace the certificate' : 'Choose a certificate type'}
                </Text>
                <InfoPopover title="Device vs Aggregator certificates">
                  <strong>Device</strong> certificates identify a single piece of equipment (e.g. a
                  battery or meter) and sit on the device signing chain. <strong>Aggregator</strong>{' '}
                  certificates identify an organisation acting on behalf of many devices; they sit
                  on the aggregator chain and embed your notification domain in the SAN, so the
                  utility server can deliver subscription notifications back to you. Both chain to
                  the same root that the utility server trusts.
                </InfoPopover>
              </Flex>

              <Flex justify="end" gap="2" wrap="wrap">
                {hasCert && (
                  <Button asChild variant="outline">
                    <a href={`/config/run_group/${runGroup.run_group_id}/cert`}>
                      <IconDownload size={14} />
                      Download Existing Certificate
                    </a>
                  </Button>
                )}

                <form
                  method="POST"
                  action={`/config/run_group/${runGroup.run_group_id}/cert`}
                  target={`hiddenFrame-${runGroup.run_group_id}-device`}
                  onSubmit={handleFormSubmit}
                  style={{ display: 'inline' }}
                >
                  <input type="hidden" name="type" value="device" />
                  <Button type="submit" variant="outline" color={hasCert ? 'red' : 'blue'}>
                    {hasCert ? <IconRecycle size={14} /> : <IconPlus size={14} />}
                    {hasCert ? 'Replace with Device Certificate' : 'Generate Device Certificate'}
                  </Button>
                </form>

                {hasDomain ? (
                  <form
                    method="POST"
                    action={`/config/run_group/${runGroup.run_group_id}/cert`}
                    target={`hiddenFrame-${runGroup.run_group_id}-agg`}
                    onSubmit={handleFormSubmit}
                    style={{ display: 'inline' }}
                  >
                    <input type="hidden" name="type" value="aggregator" />
                    <Button type="submit" variant="outline" color={hasCert ? 'red' : 'blue'}>
                      {hasCert ? <IconRecycle size={14} /> : <IconPlus size={14} />}
                      {hasCert
                        ? 'Replace with Aggregator Certificate'
                        : 'Generate Aggregator Certificate'}
                    </Button>
                  </form>
                ) : (
                  <Tooltip content="Set a notification domain first - an aggregator certificate requires it.">
                    <Button variant="outline" color="gray" disabled>
                      {hasCert ? <IconRecycle size={14} /> : <IconPlus size={14} />}
                      {hasCert
                        ? 'Replace with Aggregator Certificate'
                        : 'Generate Aggregator Certificate'}
                    </Button>
                  </Tooltip>
                )}
              </Flex>
            </Flex>
            <iframe
              name={`hiddenFrame-${runGroup.run_group_id}-device`}
              style={{ display: 'none' }}
              title="cert-download-device"
            />
            <iframe
              name={`hiddenFrame-${runGroup.run_group_id}-agg`}
              style={{ display: 'none' }}
              title="cert-download-aggregator"
            />
          </>
        );
      }}
    </ModalButton>
  );
}
