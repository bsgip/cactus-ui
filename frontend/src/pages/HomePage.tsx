import { Box, Grid, Heading, Link, Separator, Text } from '@radix-ui/themes';
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

      <Box mb="4" style={{ textAlign: 'center' }}>
        <Heading as="h1" size="8" weight="light">
          Welcome to CACTUS
        </Heading>
        <Text as="div" size="5" color="gray">
          CSIP-Australia client testing for utility services
        </Text>
      </Box>

      <Separator my="5" size="4" />

      <Box style={{ maxWidth: 800, margin: '0 auto' }}>
        <Heading as="h2" size="6" mb="3">
          Getting Started
        </Heading>
        <ol style={{ paddingLeft: 20, marginBottom: 24 }}>
          <li style={{ marginBottom: 8 }}>
            <strong>Configure:</strong> Create run groups to manage the various devices you wish to
            certify and download their certificates from the <Link href="/config">Config page</Link>{' '}
            for use in your client. Optionally enable your domain for notifications here too.
          </li>
          <li style={{ marginBottom: 8 }}>
            <strong>Test:</strong> Go to the <Link href="/runs">Runs page</Link>, select a test
            procedure, and click 'Start Run'. Point your client at the provided test URL.
          </li>
          <li style={{ marginBottom: 8 }}>
            <strong>Results:</strong> Once your test is complete, click 'Finalize' to download your
            test results package.
          </li>
        </ol>
      </Box>

      <Separator my="5" size="4" />

      <Heading as="h2" size="6" mb="3">
        Essential Resources
      </Heading>

      <Grid columns={{ initial: '1', md: '2' }} gap="3" mb="5">
        <SectionCard title="📚 Documentation" h="100%">
          <Text as="p" mb="1">
            <Link href="https://www.csipaus.org/documents" target="_blank">
              csipaus.org/documents
            </Link>{' '}
            contains:
          </Text>
          <ul style={{ paddingLeft: 20, margin: 0 }}>
            <li style={{ marginBottom: 8 }}>
              <strong>CSIP-AUS v1.2 Explainer Document</strong>
              <br />
              <Text size="2" color="gray">
                Certificate/LFDI/SFDI/PEN matching and ramp rate explanations
              </Text>
            </li>
            <li style={{ marginBottom: 8 }}>
              <strong>SA TS 5573:2025 Standard</strong>
              <br />
              <Text size="2" color="gray">
                Official specification
              </Text>
            </li>
            <li>
              <strong>Open source GitHub repositories</strong>
              <br />
              <Text size="2" color="gray">
                All test tools and utility server code
              </Text>
            </li>
          </ul>
        </SectionCard>
        <SectionCard title="📦 Your Test Results" h="100%">
          <Text as="p" mb="1">
            When you finalize a test run, you'll receive:
          </Text>
          <ul style={{ paddingLeft: 20, marginTop: 0, marginBottom: 8 }}>
            <li>PDF test summary with pass/fail results</li>
            <li>Complete server logs</li>
            <li>Request/response logs for debugging</li>
          </ul>
          <Text size="2" color="gray">
            Use these artifacts to troubleshoot any test failures.
          </Text>
        </SectionCard>
      </Grid>

      <Separator my="5" size="4" />

      <Box style={{ maxWidth: 900, margin: '0 auto' }}>
        <Heading as="h2" size="6" mb="3">
          Common Issues
        </Heading>
        <Box
          role="alert"
          style={{
            backgroundColor: 'var(--yellow-3)',
            border: '1px solid var(--yellow-6)',
            borderRadius: 'var(--radius-3)',
            padding: 'var(--space-3)',
          }}
        >
          <ul style={{ paddingLeft: 20, margin: 0 }}>
            <li style={{ marginBottom: 8 }}>
              <strong>XSD validation is strict</strong> – Element ordering must be correct
            </li>
            <li style={{ marginBottom: 8 }}>
              <strong>Certificate matching</strong> – Your certificate, LFDI, SFDI, and PEN must
              align correctly (see CSIP-AUS explainer document)
            </li>
            <li>
              <strong>MirrorMeterReading requirements</strong> – CSIP-AUS enforces only a subset;
              refer to SA TS 5573:2025, Table 8.1
            </li>
          </ul>
        </Box>
      </Box>

      {session.support_email && (
        <>
          <Separator my="5" size="4" />
          <Box mb="4">
            <Heading as="h2" size="6" mb="3">
              Need Help?
            </Heading>
            <Grid columns={{ initial: '1', md: '3' }} gap="3">
              <SectionCard title="🐛 Report a Bug" h="100%">
                <Link href="https://tinyurl.com/mrbu8cwt" target="_blank">
                  tinyurl.com/mrbu8cwt
                </Link>
              </SectionCard>
              <SectionCard title="📋 Standards Help" h="100%">
                <Link href="mailto:csipaus-cert@anu.edu.au">csipaus-cert@anu.edu.au</Link>
              </SectionCard>
              <SectionCard title="💬 Software Questions" h="100%">
                <Link href="mailto:support@bsgip.com">support@bsgip.com</Link>
              </SectionCard>
            </Grid>
          </Box>
        </>
      )}
    </>
  );
}
