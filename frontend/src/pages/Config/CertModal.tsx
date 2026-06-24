import { Button, Code, Group, Stack, Text } from '@mantine/core';
import { IconDownload, IconPlus, IconRecycle } from '@tabler/icons-react';
import type { RunGroupResponse } from '../../api/types';
import { ModalButton } from '../../components/ModalButton';

export function CertModal({
  runGroup,
  onCertAction,
}: {
  runGroup: RunGroupResponse;
  onCertAction: () => void;
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
        <Button
          variant={hasCert ? 'outline' : 'filled'}
          leftSection={hasCert ? <IconRecycle size={14} /> : <IconPlus size={14} />}
          onClick={open}
        >
          {hasCert ? `${certType} Certificate` : 'Generate Certificate'}
        </Button>
      )}
    >
      {(close) => {
        const handleFormSubmit = () => {
          close();
          onCertAction();
        };
        return (
          <>
            <Stack>
              {hasCert ? (
                <Text>
                  The current <Code>{certType}</Code> certificate (ID{' '}
                  <Code>{runGroup.certificate_id}</Code>) was created <Code>{certDate}</Code>
                  <br />
                  <br />
                  <strong>Note:</strong> Generating a new certificate will invalidate the current
                  certificate.
                </Text>
              ) : (
                <Text>
                  There is <strong>no</strong> certificate on record for this run group. You will
                  need to create one in order to create test runs.
                </Text>
              )}

              <Group justify="flex-end">
                {hasCert && (
                  <Button
                    component="a"
                    href={`/config/run_group/${runGroup.run_group_id}/cert`}
                    variant="outline"
                    leftSection={<IconDownload size={14} />}
                  >
                    Download Existing Certificate
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
                  <Button
                    type="submit"
                    variant="outline"
                    color={hasCert ? 'red' : 'blue'}
                    leftSection={<IconRecycle size={14} />}
                  >
                    Device Certificate
                  </Button>
                </form>

                <form
                  method="POST"
                  action={`/config/run_group/${runGroup.run_group_id}/cert`}
                  target={`hiddenFrame-${runGroup.run_group_id}-agg`}
                  onSubmit={handleFormSubmit}
                  style={{ display: 'inline' }}
                >
                  <input type="hidden" name="type" value="aggregator" />
                  <Button
                    type="submit"
                    variant="outline"
                    color={hasCert ? 'red' : 'blue'}
                    leftSection={<IconRecycle size={14} />}
                  >
                    Aggregator Certificate
                  </Button>
                </form>
              </Group>
            </Stack>
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
