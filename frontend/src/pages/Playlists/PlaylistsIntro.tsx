import { Button, Flex, Text } from '@radix-ui/themes';
import { IconInfoCircle } from '@tabler/icons-react';
import { ModalButton } from '../../components/ModalButton';

// One-line explanation of what a playlist is, with a "Learn more" popup for the full how-to.
export function PlaylistsIntro() {
  return (
    <Flex align="center" gap="2" mb="3" wrap="wrap">
      <Text size="2" color="gray">
        A playlist runs tests back-to-back against your client. Device registration persists between
        tests; other information is deleted.
      </Text>
      <ModalButton
        title="How playlists work"
        size="md"
        trigger={(open) => (
          <Button variant="ghost" size="1" onClick={open}>
            <IconInfoCircle size={15} />
            Learn more
          </Button>
        )}
      >
        {() => (
          <Flex direction="column" gap="3" mt="2">
            <Text as="p" size="2">
              Normal test runs create a new utility server and database for every test.{' '}
              <strong>Playlists use a single server for the whole playlist.</strong>
            </Text>
            <Text as="p" size="2">
              This removes per-test startup time and persists end-device registration between tests.
            </Text>
            <Text as="p" size="2">
              Most other information (readings, DERSettings, etc.) is deleted between tests, and any
              DERControls are cancelled. Clients receive notifications of the cancelled DERControls
              and can still see them when polling.
            </Text>
          </Flex>
        )}
      </ModalButton>
    </Flex>
  );
}
