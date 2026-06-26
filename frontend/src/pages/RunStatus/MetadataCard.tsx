import { Badge, Box, Button, Dialog, Flex, Separator, Table, Text } from '@radix-ui/themes';
import { SectionCard } from '../../components/SectionCard';
import { useDisclosure } from '../../hooks/useDisclosure';
import type {
  DERCapabilityInfo,
  DERSettingsInfo,
  DERStatusInfo,
  EndDeviceMetadata,
} from '../../api/types';

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
    <Text color="gray">Not set</Text>
  );
}

function unit(v: number | null | undefined, u: string) {
  return v !== null && v !== undefined ? (
    <>
      {v} {u}
    </>
  ) : (
    <Text color="gray">Not set</Text>
  );
}

function badges(items: string[] | null | undefined) {
  if (!items || items.length === 0) {
    return <Text color="gray">None</Text>;
  }
  return items.map((i) => (
    <Badge key={i} color="gray" mr="1">
      {i}
    </Badge>
  ));
}

// "Active Device Metadata" card plus the DER Details modal (capability / settings / status).
export function MetadataCard({ metadata }: Props) {
  const [opened, { open, close }] = useDisclosure(false);

  return (
    <SectionCard
      scroll
      title="Active Device Metadata"
      action={
        <Button size="1" variant="outline" color="gray" onClick={open}>
          Device Details
        </Button>
      }
    >
      <Table.Root>
        <Table.Body>
          <Table.Row>
            <Table.RowHeaderCell>End Device href</Table.RowHeaderCell>
            <Table.Cell>{value(metadata?.edevid)}</Table.Cell>
          </Table.Row>
          <Table.Row>
            <Table.RowHeaderCell>LFDI</Table.RowHeaderCell>
            <Table.Cell>{value(metadata?.lfdi)}</Table.Cell>
          </Table.Row>
          <Table.Row>
            <Table.RowHeaderCell>NMI</Table.RowHeaderCell>
            <Table.Cell>{value(metadata?.nmi)}</Table.Cell>
          </Table.Row>
          <Table.Row>
            <Table.RowHeaderCell>Set Max W (W)</Table.RowHeaderCell>
            <Table.Cell>{value(metadata?.set_max_w)}</Table.Cell>
          </Table.Row>
        </Table.Body>
      </Table.Root>

      <Dialog.Root open={opened} onOpenChange={(o) => !o && close()}>
        <Dialog.Content maxWidth="600px">
          <Dialog.Title>DER Device Details</Dialog.Title>
          <DerCapabilityCard cap={metadata?.der_capability ?? null} />
          <DerSettingsCard set={metadata?.der_settings ?? null} />
          <DerStatusCard sta={metadata?.der_status ?? null} />
        </Dialog.Content>
      </Dialog.Root>
    </SectionCard>
  );
}

function SubCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <Box
      mb="3"
      style={{
        border: '1px solid var(--gray-5)',
        borderRadius: 'var(--radius-3)',
        overflow: 'hidden',
      }}
    >
      <Flex px="3" py="2">
        <Text weight="medium">{title}</Text>
      </Flex>
      <Separator size="4" />
      <Table.Root>
        <Table.Body>{children}</Table.Body>
      </Table.Root>
    </Box>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <Table.Row>
      <Table.RowHeaderCell>{label}</Table.RowHeaderCell>
      <Table.Cell>{children}</Table.Cell>
    </Table.Row>
  );
}

function DerCapabilityCard({ cap }: { cap: DERCapabilityInfo | null }) {
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

function DerSettingsCard({ set }: { set: DERSettingsInfo | null }) {
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

function DerStatusCard({ sta }: { sta: DERStatusInfo | null }) {
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
    <Table.Row>
      <Table.Cell>
        <Text color="gray">Not set</Text>
      </Table.Cell>
    </Table.Row>
  );
}
