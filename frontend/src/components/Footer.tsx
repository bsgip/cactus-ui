import { Flex, Link, Text } from '@radix-ui/themes';
import type { SessionResponse } from '../api/types';

export function Footer({ session }: { session: SessionResponse }) {
  return (
    <footer
      style={{
        marginTop: 32,
        padding: '16px 0',
        textAlign: 'center',
        borderTop: '1px solid var(--gray-5)',
      }}
    >
      {session.hosted_images.length > 0 && (
        <>
          <Text as="div" size="2" color="gray">
            Hosted by
          </Text>
          <Flex justify="center" align="center" mt="1" gap="3" wrap="wrap">
            {session.hosted_images.map((src) => (
              <img key={src} src={src} alt="Host Logo" style={{ height: 40 }} />
            ))}
          </Flex>
        </>
      )}
      {session.version && (
        <Text as="div" size="1" mt="1" color="gray">
          <Link
            href={`https://github.com/bsgip/cactus-deploy/releases/tag/${session.version}`}
            target="_blank"
          >
            {session.version}
          </Link>
        </Text>
      )}
    </footer>
  );
}
