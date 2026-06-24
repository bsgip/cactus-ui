import { Button, Group, Menu, Stack, Text } from '@mantine/core';
import { IconRecycle } from '@tabler/icons-react';
import { ModalButton } from '../../components/ModalButton';

export function SharedCertMenu({ onCertAction }: { onCertAction: () => void }) {
  return (
    <ModalButton
      title="Generate Shared Aggregator Certificate"
      size="lg"
      trigger={(open) => (
        <Menu>
          <Menu.Target>
            <Button variant="default">Advanced Options</Button>
          </Menu.Target>
          <Menu.Dropdown>
            <Menu.Item onClick={open}>Generate Shared Aggregator Certificate</Menu.Item>
          </Menu.Dropdown>
        </Menu>
      )}
    >
      {(close) => {
        const handleApply = () => {
          close();
          onCertAction();
        };
        return (
          <>
            <Stack>
              <Text>
                A new aggregator certificate will be generated and set as the certificate for all
                run groups.
                <br />
                <br />
                <strong>Note:</strong> Generating a new aggregator certificate will replace{' '}
                <em>all</em> existing certificates for <em>all</em> run groups.
              </Text>
              <Group justify="flex-end">
                <form
                  method="POST"
                  action="/config/shared_cert"
                  target="hiddenFrame-shared"
                  onSubmit={handleApply}
                  style={{ display: 'inline' }}
                >
                  <Button
                    type="submit"
                    variant="outline"
                    color="red"
                    leftSection={<IconRecycle size={14} />}
                  >
                    Apply
                  </Button>
                </form>
              </Group>
            </Stack>
            <iframe
              name="hiddenFrame-shared"
              style={{ display: 'none' }}
              title="shared-cert-download"
            />
          </>
        );
      }}
    </ModalButton>
  );
}
