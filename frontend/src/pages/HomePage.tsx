import { Alert, Anchor, Box, Divider, Grid, List, Text, Title } from '@mantine/core';
import { Banner } from '../components/Banner';
import { SectionCard } from '../components/SectionCard';
import { useSession } from '../hooks/useSession';

export function HomePage() {
  const { data: session } = useSession();
  if (!session) {
    return null; // Layout only renders children once the session has loaded
  }

  return (
    <>
      <Banner message={session.banner_message} />

      <Box ta="center" mb="lg">
        <Title order={1} fz={48} fw={300}>
          Welcome to CACTUS
        </Title>
        <Text size="xl" c="dimmed">
          CSIP-Australia client testing for utility services
        </Text>
      </Box>

      <Divider my="xl" />

      <Box maw={800} mx="auto">
        <Title order={2} mb="md">
          Getting Started
        </Title>
        <List type="ordered" spacing="sm" mb="xl" withPadding>
          <List.Item>
            <strong>Configure:</strong> Create run groups to manage the various devices you wish to
            certify and download their certificates from the{' '}
            <Anchor href="/config">Config page</Anchor> for use in your client. Optionally enable
            your domain for notifications here too.
          </List.Item>
          <List.Item>
            <strong>Test:</strong> Go to the <Anchor href="/runs">Runs page</Anchor>, select a test
            procedure, and click 'Start Run'. Point your client at the provided test URL.
          </List.Item>
          <List.Item>
            <strong>Results:</strong> Once your test is complete, click 'Finalize' to download your
            test results package.
          </List.Item>
        </List>
      </Box>

      <Divider my="xl" />

      <Title order={2} mb="md">
        Essential Resources
      </Title>

      <Grid mb="xl">
        <Grid.Col span={{ base: 12, md: 6 }}>
          <SectionCard title="📚 Documentation" h="100%">
            <Text mb="xs">
              <Anchor href="https://www.csipaus.org/documents" target="_blank">
                csipaus.org/documents
              </Anchor>{' '}
              contains:
            </Text>
            <List spacing="sm">
              <List.Item>
                <strong>CSIP-AUS v1.2 Explainer Document</strong>
                <br />
                <Text component="span" size="sm" c="dimmed">
                  Certificate/LFDI/SFDI/PEN matching and ramp rate explanations
                </Text>
              </List.Item>
              <List.Item>
                <strong>SA TS 5573:2025 Standard</strong>
                <br />
                <Text component="span" size="sm" c="dimmed">
                  Official specification
                </Text>
              </List.Item>
              <List.Item>
                <strong>Open source GitHub repositories</strong>
                <br />
                <Text component="span" size="sm" c="dimmed">
                  All test tools and utility server code
                </Text>
              </List.Item>
            </List>
          </SectionCard>
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 6 }}>
          <SectionCard title="📦 Your Test Results" h="100%">
            <Text mb="xs">When you finalize a test run, you'll receive:</Text>
            <List spacing="xs" mb="xs">
              <List.Item>PDF test summary with pass/fail results</List.Item>
              <List.Item>Complete server logs</List.Item>
              <List.Item>Request/response logs for debugging</List.Item>
            </List>
            <Text size="sm" c="dimmed">
              Use these artifacts to troubleshoot any test failures.
            </Text>
          </SectionCard>
        </Grid.Col>
      </Grid>

      <Divider my="xl" />

      <Box maw={900} mx="auto">
        <Title order={2} mb="md">
          Common Issues
        </Title>
        <Alert color="yellow" role="alert">
          <List spacing="sm">
            <List.Item>
              <strong>XSD validation is strict</strong> – Element ordering must be correct
            </List.Item>
            <List.Item>
              <strong>Certificate matching</strong> – Your certificate, LFDI, SFDI, and PEN must
              align correctly (see CSIP-AUS explainer document)
            </List.Item>
            <List.Item>
              <strong>MirrorMeterReading requirements</strong> – CSIP-AUS enforces only a subset;
              refer to SA TS 5573:2025, Table 8.1
            </List.Item>
          </List>
        </Alert>
      </Box>

      {session.support_email && (
        <>
          <Divider my="xl" />
          <Box mb="lg">
            <Title order={2} mb="md">
              Need Help?
            </Title>
            <Grid>
              <Grid.Col span={{ base: 12, md: 4 }}>
                <SectionCard title="🐛 Report a Bug" h="100%">
                  <Anchor href="https://tinyurl.com/mrbu8cwt" target="_blank">
                    tinyurl.com/mrbu8cwt
                  </Anchor>
                </SectionCard>
              </Grid.Col>
              <Grid.Col span={{ base: 12, md: 4 }}>
                <SectionCard title="📋 Standards Help" h="100%">
                  <Anchor href="mailto:csipaus-cert@anu.edu.au">csipaus-cert@anu.edu.au</Anchor>
                </SectionCard>
              </Grid.Col>
              <Grid.Col span={{ base: 12, md: 4 }}>
                <SectionCard title="💬 Software Questions" h="100%">
                  <Anchor href="mailto:support@bsgip.com">support@bsgip.com</Anchor>
                </SectionCard>
              </Grid.Col>
            </Grid>
          </Box>
        </>
      )}
    </>
  );
}
