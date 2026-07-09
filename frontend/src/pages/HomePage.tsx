import { Box, Button, Flex, Grid, Heading, Link, Separator, Table, Text } from '@radix-ui/themes';
import { IconInfoCircle } from '@tabler/icons-react';
import type { ReactNode } from 'react';
import { Banner } from '../components/Banner';
import { InfoPopover } from '../components/InfoPopover';
import { ModalButton } from '../components/ModalButton';
import { SectionCard } from '../components/SectionCard';
import { useSession } from '../hooks/useSession';

const HELP_FORM_URL = 'https://tinyurl.com/mrbu8cwt';
const BOOKING_FORM_URL = 'https://tinyurl.com/BookingFormCSIPAUS';
const WITNESS_EMAIL = 'csipaus-cert@anu.edu.au';
// TODO: replace with the real download URL for the Client Information form.
const CLIENT_INFO_FORM_URL = '#';
// TODO: replace with the real "Book time with Laura Jones" scheduling URL.
const SERIES_MEETING_URL = '#';

// A numbered stage of the certification journey: circled step number, title, indented body.
function Step({ n, title, children }: { n: number; title: string; children: ReactNode }) {
  return (
    <Box mb="6">
      <Flex align="center" gap="3" mb="3">
        <Flex
          align="center"
          justify="center"
          style={{
            width: 32,
            height: 32,
            borderRadius: '50%',
            backgroundColor: 'var(--accent-9)',
            color: 'white',
            fontWeight: 600,
            flexShrink: 0,
          }}
        >
          {n}
        </Flex>
        <Heading as="h2" size="6">
          {title}
        </Heading>
      </Flex>
      <Box pl={{ initial: '0', sm: '7' }} style={{ marginLeft: 4 }}>
        {children}
      </Box>
    </Box>
  );
}

function AppointmentsModal() {
  return (
    <ModalButton
      title="The two appointment types"
      size="lg"
      trigger={(open) => (
        <Button variant="soft" size="2" onClick={open}>
          <IconInfoCircle size={15} />
          What appointments will I book?
        </Button>
      )}
    >
      {() => (
        <Flex direction="column" gap="3" mt="2">
          <Box>
            <Heading as="h3" size="3" mb="1">
              System Check (30 minutes) — book this first
            </Heading>
            <ul style={{ paddingLeft: 20, margin: 0 }}>
              <li>Helps you prepare your equipment and camera setup</li>
              <li>We check that we can see your meters clearly on camera or screen share</li>
              <li>You can ask questions about the setup</li>
            </ul>
            <Text as="p" size="2" color="gray" mt="1">
              You must complete a System Check before booking a Witness Test.{' '}
              <strong>Exception:</strong> if you have completed witness tests with us before, you
              can skip this step.
            </Text>
          </Box>
          <Box>
            <Heading as="h3" size="3" mb="1">
              Witness Test (3 hours) — waitlisted
            </Heading>
            <ul style={{ paddingLeft: 20, margin: 0 }}>
              <li>The main certification test</li>
              <li>You run tests in the CACTUS platform while we watch</li>
              <li>We must see your meters clearly during all tests</li>
              <li>We will check your system setup even if you did a System Check appointment</li>
            </ul>
          </Box>
        </Flex>
      )}
    </ModalButton>
  );
}

function InverterSeriesModal() {
  return (
    <ModalButton
      title="Inverter series explained"
      size="xl"
      trigger={(open) => (
        <Link href="#" onClick={(e) => (e.preventDefault(), open())}>
          Do I need to certify every model? (Inverter series explained)
        </Link>
      )}
    >
      {() => (
        <Flex direction="column" gap="3" mt="2">
          <Text as="p" size="2">
            Devices that share the same software and physical architecture and
            differ only in capacity (e.g. power rating, phase count) belong to the same{' '}
            <strong>series</strong>, and only one representative device from a series needs to be
            certified to cover the whole series.
          </Text>
          <Text as="p" size="2">
            <strong>Series for CSIP-AUS is different to AS4777</strong> — devices that are in
            different series for AS4777 purposes may be in the same series for CSIP-AUS purposes, so
            don't assume your AS4777 groupings carry over.
          </Text>
          <Text as="p" size="2">
            Section 5.2 of the Testing and Certification Handbook sets out the full criteria. In
            general, any inverters that implement the same upstream control interface and internal
            control architecture can be grouped into one series. OEMs nominate their own series
            groupings to us, and take overall responsibility for ensuring every device in a nominated
            series is actually compliant. An example series grouping:
          </Text>
          <Table.Root size="1" variant="surface">
            <Table.Header>
              <Table.Row>
                <Table.ColumnHeaderCell>Series</Table.ColumnHeaderCell>
                <Table.ColumnHeaderCell>Control board</Table.ColumnHeaderCell>
                <Table.ColumnHeaderCell>Inverter hardware</Table.ColumnHeaderCell>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              <Table.Row>
                <Table.Cell>Series 1</Table.Cell>
                <Table.Cell>Interface 1 (e.g. SunSpec Modbus), architecture 1</Table.Cell>
                <Table.Cell>1-phase solar only</Table.Cell>
              </Table.Row>
              <Table.Row>
                <Table.Cell>Series 1</Table.Cell>
                <Table.Cell>Interface 1 (e.g. SunSpec Modbus), architecture 1</Table.Cell>
                <Table.Cell>1-phase hybrid inverter</Table.Cell>
              </Table.Row>
              <Table.Row>
                <Table.Cell>Series 1</Table.Cell>
                <Table.Cell>Interface 1 (e.g. SunSpec Modbus), architecture 1</Table.Cell>
                <Table.Cell>3-phase hybrid inverter</Table.Cell>
              </Table.Row>
              <Table.Row>
                <Table.Cell>Series 2</Table.Cell>
                <Table.Cell>Interface 2 (e.g. 2030.5), architecture 1</Table.Cell>
                <Table.Cell>1-phase solar only</Table.Cell>
              </Table.Row>
              <Table.Row>
                <Table.Cell>Series 2</Table.Cell>
                <Table.Cell>Interface 2 (e.g. 2030.5), architecture 1</Table.Cell>
                <Table.Cell>3-phase solar only</Table.Cell>
              </Table.Row>
              <Table.Row>
                <Table.Cell>Series 3</Table.Cell>
                <Table.Cell>Interface 1 (e.g. SunSpec Modbus), architecture 2</Table.Cell>
                <Table.Cell>3-phase hybrid inverter</Table.Cell>
              </Table.Row>
            </Table.Body>
          </Table.Root>
          <Text as="p" size="2">
            To discuss the most relevant series split for your products,{' '}
            <Link href={SERIES_MEETING_URL} target="_blank">
              book a 30-minute meeting with Laura Jones
            </Link>
            .
          </Text>
        </Flex>
      )}
    </ModalButton>
  );
}

function SelfTestTipsModal() {
  return (
    <ModalButton
      title="Common self-test issues"
      size="md"
      trigger={(open) => (
        <Link href="#" onClick={(e) => (e.preventDefault(), open())}>
          Why is my self-test failing?
        </Link>
      )}
    >
      {() => (
        <ul style={{ paddingLeft: 20, margin: 0, marginTop: 8 }}>
          <li style={{ marginBottom: 8 }}>
            <strong>XSD validation is strict</strong> – Element ordering must be correct
          </li>
          <li style={{ marginBottom: 8 }}>
            <strong>Certificate matching</strong> – Your certificate, LFDI, SFDI, and PEN must align
            correctly (see CSIP-AUS explainer document)
          </li>
          <li>
            <strong>MirrorMeterReading requirements</strong> – CSIP-AUS enforces only a subset;
            refer to SA TS 5573:2025, Table 8.1
          </li>
        </ul>
      )}
    </ModalButton>
  );
}

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
        <Text as="div" size="3" color="gray" mt="2">
          This page is your guide to CSIP-AUS certification — return to it anytime via{' '}
          <strong>Home</strong> in the navigation bar.
        </Text>
      </Box>

      <Separator my="5" size="4" />

      <Box style={{ maxWidth: 850, margin: '0 auto' }}>
        <Heading as="h2" size="7" mb="5" style={{ textAlign: 'center' }}>
          Your path to certification
        </Heading>

        <Step n={1} title="Self-test your device">
          <ol style={{ paddingLeft: 20, margin: 0, marginBottom: 12 }}>
            <li style={{ marginBottom: 8 }}>
              <strong>Configure:</strong> Follow the instructions on the <Link href="/config">Config page</Link> to manage the devices you want to certify, and obtain certificates.
            </li>
            <li style={{ marginBottom: 8 }}>
              <strong>Test:</strong> On the <Link href="/runs">Runs page</Link> — select a
              test procedure, click 'Start Run', and point your client at the provided test URL.
              Once you're comfortable, the <Link href="/playlists">Playlists page</Link> can queue
              several tests to run back-to-back.
            </li>
            <li>
              <strong>Results:</strong> Once your test is complete, click 'Finalize' to download
              your test results package.{' '}
              <InfoPopover title="What's in the results package?">
                A PDF test summary with pass/fail results, complete server logs, and
                request/response logs. Use these artifacts to troubleshoot any test failures.
              </InfoPopover>
            </li>
          </ol>
          <Text as="p" size="3">
            <strong>
              All required self-tests must pass before you can enrol for witness testing.
            </strong>
          </Text>
        </Step>

        <Step n={2} title="Enrol for witness testing">
          <Text as="p" mb="2">
            Due to high demand we operate a waitlist — only systems that have completed self-testing
            can be waitlisted.
          </Text>
          <AppointmentsModal />
          <ol style={{ paddingLeft: 20, margin: 0, marginTop: 12, marginBottom: 12 }}>
            <li style={{ marginBottom: 8 }}>
              Fill in our{' '}
              <Link href={BOOKING_FORM_URL} target="_blank">
                booking form
              </Link>{' '}
              — <strong>one form for each witness test you need</strong>.
            </li>
            <li style={{ marginBottom: 8 }}>
              Registration requires a completed{' '}
              <Link href={CLIENT_INFO_FORM_URL} target="_blank">
                Client Information form
              </Link>
              .
            </li>
            <li>
              A team member will contact you after you submit the form. Due to high demand, this can
              take several days.
            </li>
          </ol>
        </Step>

        <Step n={3} title="Witness testing">
          <Text as="p" mb="2">
            Once you're enrolled, the process is:
          </Text>
          <ol style={{ paddingLeft: 20, margin: 0, marginBottom: 12 }}>
            <li style={{ marginBottom: 8 }}>
              Attend your <strong>System Check</strong> — a live 30-minute meeting to verify your
              equipment and camera setup.
            </li>
            <li style={{ marginBottom: 8 }}>
              Attend your live <strong>Witness Test</strong>, running tests in CACTUS while we
              watch.
            </li>
            <li>
              You may then be asked to book further tests, or to complete some tests offline and
              send through videos of the tests being conducted.
            </li>
          </ol>
          <Text as="p" size="2" color="gray">
            Witness testing questions: <Link href={`mailto:${WITNESS_EMAIL}`}>{WITNESS_EMAIL}</Link>
          </Text>
        </Step>

        <Step n={4} title="Generate compliance reports">
          <Text as="p">
            After witness testing is completed, use the <Link href="/compliance">Compliance</Link>{' '}
            tab to generate the reports we will submit to the CEC.
          </Text>
        </Step>
      </Box>

      <Separator my="5" size="4" />

      <Heading as="h2" size="6" mb="3">
        Help & Resources
      </Heading>

      <Grid columns={{ initial: '1', md: '3' }} gap="3" mb="4">
        <SectionCard title="📚 Standards & Documentation" h="100%">
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
              <strong>Testing and Certification Handbook</strong>
              <br />
              <Text size="2" color="gray">
                For more information about the ANU testing process
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
        <SectionCard title="❓ Common Questions" h="100%">
          <ul style={{ paddingLeft: 20, margin: 0 }}>
            <li style={{ marginBottom: 8 }}>
              <InverterSeriesModal />
            </li>
            <li>
              <SelfTestTipsModal />
            </li>
          </ul>
        </SectionCard>
        <SectionCard title="📬 Get in touch" h="100%">
          <Box mb="3">
            <Text as="p" size="2" weight="medium" mb="1">
              Standards, self-testing & CACTUS platform
            </Text>
            <Text as="p" size="2" color="gray" mb="1">
              Questions about the standards, self-testing, or the CACTUS platform (including bug
              reports):
            </Text>
            <Link href={HELP_FORM_URL} target="_blank">
              Submit a help request
            </Link>
          </Box>
          <Box>
            <Text as="p" size="2" weight="medium" mb="1">
              Witness testing
            </Text>
            <Text as="p" size="2" color="gray" mb="1">
              All witness-testing related questions:
            </Text>
            <Link href={`mailto:${WITNESS_EMAIL}`}>{WITNESS_EMAIL}</Link>
          </Box>
        </SectionCard>
      </Grid>
    </>
  );
}
