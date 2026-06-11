import { Anchor, Box, Group, Text } from '@mantine/core';
import type { SessionResponse } from '../api/types';

export function Footer({ session }: { session: SessionResponse }) {
  return (
    <Box
      component="footer"
      mt="xl"
      py="md"
      ta="center"
      c="dimmed"
      style={{ borderTop: '1px solid var(--mantine-color-gray-3)' }}
    >
      {session.hosted_images.length > 0 && (
        <>
          <Text size="sm">Hosted by</Text>
          <Group justify="center" mt="xs" gap="md" wrap="wrap">
            {session.hosted_images.map((src) => (
              <img key={src} src={src} alt="Host Logo" style={{ height: 40 }} />
            ))}
          </Group>
        </>
      )}
      {session.version && (
        <Text size="xs" mt="xs">
          <Anchor
            href={`https://github.com/bsgip/cactus-deploy/releases/tag/${session.version}`}
            target="_blank"
          >
            {session.version}
          </Anchor>
        </Text>
      )}
    </Box>
  );
}
