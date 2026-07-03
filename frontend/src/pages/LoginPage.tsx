import { Button, Callout, Flex, Heading, Text } from '@radix-ui/themes';

// Shown when /api/session returns 401. The login banner message comes from the
// LOGIN_BANNER_MESSAGE envvar and may contain HTML (rendered via dangerouslySetInnerHTML).
export function LoginPage({ loginBannerMessage }: { loginBannerMessage: string | null }) {
  return (
    <Flex direction="column" style={{ minHeight: '100vh', backgroundColor: 'var(--gray-2)' }}>
      <Flex
        direction="column"
        align="center"
        justify="center"
        gap="3"
        style={{ flexGrow: 1, textAlign: 'center' }}
      >
        <Heading as="h1" size="8">
          🌵 Welcome to CACTUS
        </Heading>
        <Heading as="h2" size="5" weight="medium" color="gray">
          Client Testing Harness
        </Heading>
        <Button asChild color="green">
          <a href="/login">Login</a>
        </Button>
        {loginBannerMessage && (
          <Callout.Root color="amber" role="alert" style={{ maxWidth: 600 }}>
            <Callout.Text>
              <span dangerouslySetInnerHTML={{ __html: loginBannerMessage }} />
            </Callout.Text>
          </Callout.Root>
        )}
      </Flex>
      <Text as="div" align="center" color="gray" size="2" style={{ paddingBottom: 20 }}>
        <strong>C.A.C.T.U.S.</strong> = CSIP-Australia Compliance Testing for Utility Services
      </Text>
    </Flex>
  );
}
