import { Badge, Button, Card, Group, Modal, Table, Text, Title } from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import type { DerCapabilityInfo, DerSettingsInfo, DerStatusInfo, EndDeviceMetadata } from '../../api/types';

interface Props {
  metadata: EndDeviceMetadata | null;
}

function value(v: string | number | null | undefined) {
  return v !== null && v !== undefined ? String(v) : 'Not set';
}

function notSet(v: string | number | null | undefined) {
  return v !== null && v !== undefined ? (
    <>{v}</>
  ) : (
    <Text span c="dimmed">
      Not set
    </Text>
  );
}

function unit(v: number | null | undefined, u: string) {
  return v !== null && v !== undefined ? (
    <>
      {v} {u}
    </>
  ) : (
    <Text span c="dimmed">
      Not set
    </Text>
  );
}

function badges(items: string[] | null | undefined) {
  if (!items || items.length === 0) {
    return (
      <Text span c="dimmed">
        None
      </Text>
    );
  }
  return items.map((i) => (
    <Badge key={i} color="gray" mr={4}>
      {i}
    </Badge>
  ));
}

// "Active Device Metadata" card plus the DER Details modal (capability / settings / status).
// Ported from run_status.html metadataTableBody + derDetailsModalBody.
export function MetadataCard({ metadata }: Props) {
  const [opened, { open, close }] = useDisclosure(false);

  return (
    <Card withBorder style={{ maxHeight: 600, overflowY: 'auto' }}>
      <Group justify="space-between" mb="xs">
        <Title order={5}>Active Device Metadata</Title>
        <Button size="xs" variant="outline" color="gray" onClick={open}>
          Device Details
        </Button>
      </Group>
      <Table>
        <Table.Tbody>
          <Table.Tr>
            <Table.Th>End Device href</Table.Th>
            <Table.Td>{value(metadata?.edevid)}</Table.Td>
          </Table.Tr>
          <Table.Tr>
            <Table.Th>LFDI</Table.Th>
            <Table.Td>{value(metadata?.lfdi)}</Table.Td>
          </Table.Tr>
          <Table.Tr>
            <Table.Th>NMI</Table.Th>
            <Table.Td>{value(metadata?.nmi)}</Table.Td>
          </Table.Tr>
          <Table.Tr>
            <Table.Th>Set Max W (W)</Table.Th>
            <Table.Td>{value(metadata?.set_max_w)}</Table.Td>
          </Table.Tr>
        </Table.Tbody>
      </Table>

      <Modal opened={opened} onClose={close} title="DER Device Details" size="lg">
        <DerCapabilityCard cap={metadata?.der_capability ?? null} />
        <DerSettingsCard set={metadata?.der_settings ?? null} />
        <DerStatusCard sta={metadata?.der_status ?? null} />
      </Modal>
    </Card>
  );
}

function SubCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <Card withBorder mb="md" padding={0}>
      <Card.Section withBorder inheritPadding py="xs">
        <Text fw={600}>{title}</Text>
      </Card.Section>
      <Table>
        <Table.Tbody>{children}</Table.Tbody>
      </Table>
    </Card>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <Table.Tr>
      <Table.Th>{label}</Table.Th>
      <Table.Td>{children}</Table.Td>
    </Table.Tr>
  );
}

function DerCapabilityCard({ cap }: { cap: DerCapabilityInfo | null }) {
  return (
    <SubCard title="DER Capability">
      {cap ? (
        <>
          <Row label="DER Type">{notSet(cap.der_type)}</Row>
          <Row label="Modes Supported">{badges(cap.modes_supported)}</Row>
          <Row label="Max W">{unit(cap.max_w, 'W')}</Row>
          <Row label="Max VA">{unit(cap.max_va, 'VA')}</Row>
          <Row label="Max VAR">{unit(cap.max_var, 'VA')}</Row>
          <Row label="Max VAR (neg)">{unit(cap.max_var_neg, 'VA')}</Row>
          <Row label="Max A">{unit(cap.max_a, 'A')}</Row>
          <Row label="Max Charge Rate">{unit(cap.max_charge_rate_w, 'W')}</Row>
          <Row label="Max Discharge Rate">{unit(cap.max_discharge_rate_w, 'W')}</Row>
          <Row label="Max Wh">{unit(cap.max_wh, 'Wh')}</Row>
          <Row label="DOE Modes Supported">{badges(cap.doe_modes_supported)}</Row>
        </>
      ) : (
        <NotSetRow />
      )}
    </SubCard>
  );
}

function DerSettingsCard({ set }: { set: DerSettingsInfo | null }) {
  return (
    <SubCard title="DER Settings">
      {set ? (
        <>
          <Row label="Modes Enabled">{badges(set.modes_enabled)}</Row>
          <Row label="Max W">{unit(set.max_w, 'W')}</Row>
          <Row label="Max VA">{unit(set.max_va, 'VA')}</Row>
          <Row label="Max VAR">{unit(set.max_var, 'VA')}</Row>
          <Row label="Max VAR (neg)">{unit(set.max_var_neg, 'VA')}</Row>
          <Row label="Max Charge Rate">{unit(set.max_charge_rate_w, 'W')}</Row>
          <Row label="Max Discharge Rate">{unit(set.max_discharge_rate_w, 'W')}</Row>
          <Row label="setGradW">{notSet(set.grad_w)}</Row>
          <Row label="DOE Modes Enabled">{badges(set.doe_modes_enabled)}</Row>
        </>
      ) : (
        <NotSetRow />
      )}
    </SubCard>
  );
}

function DerStatusCard({ sta }: { sta: DerStatusInfo | null }) {
  return (
    <SubCard title="DER Status">
      {sta ? (
        <>
          <Row label="Alarm Status">{badges(sta.alarm_status)}</Row>
          <Row label="Generator Connect Status">{badges(sta.generator_connect_status)}</Row>
          <Row label="Storage Connect Status">{badges(sta.storage_connect_status)}</Row>
          <Row label="Inverter Status">{notSet(sta.inverter_status)}</Row>
          <Row label="Operational Mode">{notSet(sta.operational_mode_status)}</Row>
          <Row label="Storage Mode">{notSet(sta.storage_mode_status)}</Row>
          <Row label="Local Control Mode">{notSet(sta.local_control_mode_status)}</Row>
          <Row label="Manufacturer Status">{notSet(sta.manufacturer_status)}</Row>
          <Row label="State of Charge">{notSet(sta.state_of_charge_status)}</Row>
        </>
      ) : (
        <NotSetRow />
      )}
    </SubCard>
  );
}

function NotSetRow() {
  return (
    <Table.Tr>
      <Table.Td>
        <Text span c="dimmed">
          Not set
        </Text>
      </Table.Td>
    </Table.Tr>
  );
}
