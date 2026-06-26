import { Button, DropdownMenu, Flex, Text } from '@radix-ui/themes';
import { IconRecycle } from '@tabler/icons-react';
import { ModalButton } from '../../components/ModalButton';

export function SharedCertMenu({ onCertAction }: { onCertAction: () => void }) {
  return (
    <ModalButton
      title="Generate Shared Aggregator Certificate"
      size="lg"
      trigger={(open) => (
        <DropdownMenu.Root>
          <DropdownMenu.Trigger>
            <Button variant="soft" color="gray">
              Advanced Options
            </Button>
          </DropdownMenu.Trigger>
          <DropdownMenu.Content>
            <DropdownMenu.Item onSelect={open}>
              Generate Shared Aggregator Certificate
            </DropdownMenu.Item>
          </DropdownMenu.Content>
        </DropdownMenu.Root>
      )}
    >
      {(close) => {
        const handleApply = () => {
          close();
          onCertAction();
        };
        return (
          <>
            <Flex direction="column" gap="3">
              <Text>
                A new aggregator certificate will be generated and set as the certificate for all
                run groups.
                <br />
                <br />
                <strong>Note:</strong> Generating a new aggregator certificate will replace{' '}
                <em>all</em> existing certificates for <em>all</em> run groups.
              </Text>
              <Flex justify="end">
                <form
                  method="POST"
                  action="/config/shared_cert"
                  target="hiddenFrame-shared"
                  onSubmit={handleApply}
                  style={{ display: 'inline' }}
                >
                  <Button type="submit" variant="outline" color="red">
                    <IconRecycle size={14} />
                    Apply
                  </Button>
                </form>
              </Flex>
            </Flex>
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
