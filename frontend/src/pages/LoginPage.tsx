import { Alert, Box, Button, Stack, Text, Title } from '@mantine/core';

// Port of login.html: shown when /api/session returns 401. The login banner message
// comes from the LOGIN_BANNER_MESSAGE envvar and was rendered with `| safe` in Jinja.
export function LoginPage({ loginBannerMessage }: { loginBannerMessage: string | null }) {
  return (
    <Box bg="gray.0" mih="100vh" display="flex" style={{ flexDirection: 'column' }}>
      <Stack align="center" justify="center" ta="center" gap="md" style={{ flexGrow: 1 }}>
        <Title order={1}>🌵 Welcome to CACTUS</Title>
        <Title order={2} fz="h5" fw={500} c="dimmed">
          Client Testing Harness
        </Title>
        <Button component="a" href="/login" color="green">
          Login
        </Button>
        {loginBannerMessage && (
          <Alert color="red" maw={600} role="alert">
            <span dangerouslySetInnerHTML={{ __html: loginBannerMessage }} />
          </Alert>
        )}
      </Stack>
      <Text ta="center" c="dimmed" size="sm" pb={20}>
        <strong>C.A.C.T.U.S.</strong> = CSIP-Australia Compliance Testing for Utility Services
      </Text>
    </Box>
  );
}
