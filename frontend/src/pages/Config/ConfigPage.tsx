import {
  Alert,
  Badge,
  Button,
  Card,
  Code,
  Divider,
  Group,
  Menu,
  Modal,
  NumberInput,
  SimpleGrid,
  Skeleton,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
} from '@mantine/core';
import { useDisclosure, useDocumentTitle } from '@mantine/hooks';
import {
  IconAlertTriangle,
  IconArrowsLeftRight,
  IconDownload,
  IconPencil,
  IconPlus,
  IconRecycle,
  IconTrash,
} from '@tabler/icons-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  createRunGroup,
  deleteRunGroup,
  fetchConfig,
  updateDomain,
  updatePen,
  updateRunGroupName,
  updateRunGroupStaticUri,
} from '../../api/config';
import type { RunGroupResponse } from '../../api/types';
import { Banner } from '../../components/Banner';
import { ErrorAlert } from '../../components/ErrorAlert';
import { useSession } from '../../hooks/useSession';

// After a cert form submission (which downloads a file via iframe/form), wait 1.5 s
// then invalidate so the run group list reflects any cert changes.
const CERT_RELOAD_DELAY_MS = 1500;

function CertModal({
  runGroup,
  onCertAction,
}: {
  runGroup: RunGroupResponse;
  onCertAction: () => void;
}) {
  const [opened, { open, close }] = useDisclosure(false);
  const hasCert = !!(runGroup.certificate_id && runGroup.certificate_created_at);
  const certType = runGroup.is_device_cert ? 'Device' : 'Aggregator';
  const certDate = runGroup.certificate_created_at
    ? new Date(runGroup.certificate_created_at).toLocaleDateString('sv')
    : null;

  const handleFormSubmit = () => {
    close();
    onCertAction();
  };

  return (
    <>
      <Button
        variant={hasCert ? 'outline' : 'filled'}
        leftSection={hasCert ? <IconRecycle size={14} /> : <IconPlus size={14} />}
        onClick={open}
      >
        {hasCert ? `${certType} Certificate` : 'Generate Certificate'}
      </Button>

      <Modal opened={opened} onClose={close} title={`Certificate for ${runGroup.name}`} size="lg">
        <Stack>
          {hasCert ? (
            <Text>
              The current <Code>{certType}</Code> certificate (ID{' '}
              <Code>{runGroup.certificate_id}</Code>) was created <Code>{certDate}</Code>
              <br />
              <br />
              <strong>Note:</strong> Generating a new certificate will invalidate the current
              certificate.
            </Text>
          ) : (
            <Text>
              There is <strong>no</strong> certificate on record for this run group. You will need
              to create one in order to create test runs.
            </Text>
          )}

          <Group justify="flex-end">
            {hasCert && (
              <Button
                component="a"
                href={`/config/run_group/${runGroup.run_group_id}/cert`}
                variant="outline"
                leftSection={<IconDownload size={14} />}
              >
                Download Existing Certificate
              </Button>
            )}

            <form
              method="POST"
              action={`/config/run_group/${runGroup.run_group_id}/cert`}
              target={`hiddenFrame-${runGroup.run_group_id}-device`}
              onSubmit={handleFormSubmit}
              style={{ display: 'inline' }}
            >
              <input type="hidden" name="type" value="device" />
              <Button
                type="submit"
                variant="outline"
                color={hasCert ? 'red' : 'blue'}
                leftSection={<IconRecycle size={14} />}
              >
                Device Certificate
              </Button>
            </form>

            <form
              method="POST"
              action={`/config/run_group/${runGroup.run_group_id}/cert`}
              target={`hiddenFrame-${runGroup.run_group_id}-agg`}
              onSubmit={handleFormSubmit}
              style={{ display: 'inline' }}
            >
              <input type="hidden" name="type" value="aggregator" />
              <Button
                type="submit"
                variant="outline"
                color={hasCert ? 'red' : 'blue'}
                leftSection={<IconRecycle size={14} />}
              >
                Aggregator Certificate
              </Button>
            </form>
          </Group>
        </Stack>
        <iframe
          name={`hiddenFrame-${runGroup.run_group_id}-device`}
          style={{ display: 'none' }}
          title="cert-download-device"
        />
        <iframe
          name={`hiddenFrame-${runGroup.run_group_id}-agg`}
          style={{ display: 'none' }}
          title="cert-download-aggregator"
        />
      </Modal>
    </>
  );
}

function DeleteModal({
  runGroup,
  onDelete,
  isDeleting,
}: {
  runGroup: RunGroupResponse;
  onDelete: () => void;
  isDeleting: boolean;
}) {
  const [opened, { open, close }] = useDisclosure(false);
  return (
    <>
      <Button variant="outline" color="red" leftSection={<IconTrash size={14} />} onClick={open}>
        Delete
      </Button>
      <Modal opened={opened} onClose={close} title="Confirm Delete">
        <Stack>
          <Text>
            You are about to permanently delete <strong>{runGroup.name}</strong>{' '}
            <Code>{runGroup.csip_aus_version}</Code>. Once deleted, this group and the associated{' '}
            {runGroup.total_runs} run(s) will be gone forever.
          </Text>
          <Group justify="flex-end">
            <Button variant="default" onClick={close}>
              Cancel
            </Button>
            <Button
              color="red"
              leftSection={<IconTrash size={14} />}
              loading={isDeleting}
              onClick={() => {
                onDelete();
                close();
              }}
            >
              Delete {runGroup.name}
            </Button>
          </Group>
        </Stack>
      </Modal>
    </>
  );
}

export function ConfigPage() {
  useDocumentTitle('Certificate - CACTUS');
  const { data: session } = useSession();
  const queryClient = useQueryClient();

  const [actionError, setActionError] = useState<string | null>(null);
  const [penValue, setPenValue] = useState<string | number>('');
  const [domainValue, setDomainValue] = useState('');
  const [editNames, setEditNames] = useState<Record<number, string>>({});
  const pendingDeleteRef = useRef<number | null>(null);

  const configQuery = useQuery({
    queryKey: ['config'],
    queryFn: fetchConfig,
    // Pre-populate the form fields once loaded (only on initial load)
    select: (data) => data,
  });

  const invalidateConfig = () => void queryClient.invalidateQueries({ queryKey: ['config'] });
  const onError = (err: Error) => setActionError(err.message);

  // Sync form fields when config loads for the first time
  const config = configQuery.data;
  const [initialised, setInitialised] = useState(false);
  if (config && !initialised) {
    setPenValue(config.config.pen ?? '');
    setDomainValue(config.config.subscription_domain);
    setInitialised(true);
  }

  const penMutation = useMutation({
    mutationFn: () => updatePen(Number(penValue)),
    onSuccess: () => {
      setActionError(null);
      invalidateConfig();
    },
    onError,
  });

  const domainMutation = useMutation({
    mutationFn: () => updateDomain(domainValue),
    onSuccess: () => {
      setActionError(null);
      invalidateConfig();
    },
    onError,
  });

  const staticUriMutation = useMutation({
    mutationFn: ({ id, is_static_uri }: { id: number; is_static_uri: boolean }) =>
      updateRunGroupStaticUri(id, is_static_uri),
    onSuccess: () => {
      setActionError(null);
      invalidateConfig();
    },
    onError,
  });

  const createGroupMutation = useMutation({
    mutationFn: (version: string) => createRunGroup(version, false),
    onSuccess: () => {
      setActionError(null);
      invalidateConfig();
    },
    onError,
  });

  const updateNameMutation = useMutation({
    mutationFn: ({ id, name }: { id: number; name: string }) => updateRunGroupName(id, name),
    onSuccess: () => {
      setActionError(null);
      invalidateConfig();
    },
    onError,
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => deleteRunGroup(id),
    onSuccess: () => {
      setActionError(null);
      invalidateConfig();
    },
    onError,
  });

  const handleCertAction = () => {
    setTimeout(invalidateConfig, CERT_RELOAD_DELAY_MS);
  };

  const runGroups = config?.run_groups ?? [];
  const csipVersions = config?.csip_aus_versions ?? [];

  return (
    <>
      <Banner message={session?.banner_message} />
      <Title order={2} mb="md">
        User Configuration
      </Title>
      <Text mb="md">
        The following configuration options will apply to all future{' '}
        <Text component={Link} to="/runs" c="blue" inherit>
          Runs
        </Text>{' '}
        that are created.
      </Text>
      <Divider mb="md" />

      {actionError && <ErrorAlert message={actionError} />}

      {configQuery.isPending ? (
        <Stack>
          <Skeleton height={200} />
          <Skeleton height={200} />
        </Stack>
      ) : configQuery.error ? (
        <ErrorAlert message="Unable to communicate with test server. Please try refreshing the page or re-logging in." />
      ) : (
        <Stack gap="md">
          {runGroups.length === 0 && (
            <Alert color="red" icon={<IconAlertTriangle size={16} />} role="alert">
              There are no Run Groups configured. Please create one below in order to start testing.
            </Alert>
          )}

          {/* Run Groups card */}
          <Card withBorder>
            <Title order={5} mb="xs">
              Run Groups
            </Title>
            <Text mb="xs">
              Each run group represents progress towards certification for a single device / client.
            </Text>
            <Text mb="sm">
              All certificates will be signed by the CACTUS certificate authority.
            </Text>

            <Group mb="md">
              <Button
                component="a"
                href="/config/ca_cert"
                variant="outline"
                leftSection={<IconDownload size={14} />}
              >
                Download SERCA Certificate
              </Button>

              {runGroups.length > 1 && <SharedCertMenu onCertAction={handleCertAction} />}
            </Group>

            {runGroups.length === 0 ? (
              <Text fw={700}>There doesn&apos;t seem to be anything here...</Text>
            ) : (
              <Table>
                <Table.Tbody>
                  {runGroups.map((rg) => (
                    <Table.Tr key={rg.run_group_id}>
                      <Table.Td>
                        <CertModal runGroup={rg} onCertAction={handleCertAction} />
                      </Table.Td>
                      <Table.Td>
                        <Group gap="xs">
                          <TextInput
                            value={editNames[rg.run_group_id] ?? rg.name}
                            onChange={(e) =>
                              setEditNames((prev) => ({
                                ...prev,
                                [rg.run_group_id]: e.target.value,
                              }))
                            }
                            style={{ flex: 1 }}
                          />
                          <Button
                            variant="outline"
                            loading={
                              updateNameMutation.isPending &&
                              updateNameMutation.variables?.id === rg.run_group_id
                            }
                            onClick={() =>
                              updateNameMutation.mutate({
                                id: rg.run_group_id,
                                name: editNames[rg.run_group_id] ?? rg.name,
                              })
                            }
                          >
                            Save
                          </Button>
                        </Group>
                      </Table.Td>
                      <Table.Td>
                        <Code>{rg.csip_aus_version}</Code>
                      </Table.Td>
                      <Table.Td>
                        <Stack gap={4} align="flex-start">
                          {rg.is_static_uri ? (
                            <>
                              <Badge>Static URI</Badge>
                              {rg.static_uri && (
                                <Text component="u" size="xs">
                                  {rg.static_uri}
                                </Text>
                              )}
                            </>
                          ) : (
                            <Badge color="gray">Dynamic URI</Badge>
                          )}
                          <Button
                            size="compact-xs"
                            variant="subtle"
                            leftSection={<IconArrowsLeftRight size={12} />}
                            loading={
                              staticUriMutation.isPending &&
                              staticUriMutation.variables?.id === rg.run_group_id
                            }
                            onClick={() =>
                              staticUriMutation.mutate({
                                id: rg.run_group_id,
                                is_static_uri: !rg.is_static_uri,
                              })
                            }
                          >
                            {rg.is_static_uri ? 'Swap to dynamic' : 'Swap to static'}
                          </Button>
                        </Stack>
                      </Table.Td>
                      <Table.Td>{rg.total_runs} total run(s)</Table.Td>
                      <Table.Td>
                        <DeleteModal
                          runGroup={rg}
                          isDeleting={
                            deleteMutation.isPending && pendingDeleteRef.current === rg.run_group_id
                          }
                          onDelete={() => {
                            pendingDeleteRef.current = rg.run_group_id;
                            deleteMutation.mutate(rg.run_group_id);
                          }}
                        />
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            )}

            <Group mt="md">
              {csipVersions.map((v) => (
                <Button
                  key={v.version}
                  variant="outline"
                  leftSection={<IconPlus size={14} />}
                  loading={
                    createGroupMutation.isPending && createGroupMutation.variables === v.version
                  }
                  onClick={() => createGroupMutation.mutate(v.version)}
                >
                  New {v.version} Group
                </Button>
              ))}
            </Group>
          </Card>

          {/* Config cards */}
          <SimpleGrid cols={3}>
            {/* PEN card */}
            <Card withBorder>
              <Title order={5} mb="xs">
                Private Enterprise Number (PEN)
              </Title>
              <Text mb="xs">
                A Private Enterprise Number (PEN) is a numeric identifier for an organisation,
                individual or other entity. CSIP-Aus requires clients to encode a PEN within various
                requests to the server.
              </Text>
              <Text mb="md">
                A PEN can be obtained from{' '}
                <Text component="a" href="https://www.iana.org/" c="blue" inherit>
                  IANA
                </Text>{' '}
                for free from the following{' '}
                <Text
                  component="a"
                  href="https://www.iana.org/assignments/enterprise-numbers/"
                  c="blue"
                  inherit
                >
                  link
                </Text>
                .
              </Text>
              <NumberInput
                min={1}
                max={4294967295}
                value={penValue}
                onChange={setPenValue}
                placeholder="Enter PEN (e.g. 123456)"
                mb="sm"
              />
              <Button
                leftSection={<IconPencil size={14} />}
                loading={penMutation.isPending}
                onClick={() => penMutation.mutate()}
              >
                Update PEN
              </Button>
            </Card>

            {/* Subscription Domain card */}
            <Card withBorder>
              <Title order={5} mb="xs">
                Subscription Notification Domain (Optional)
              </Title>
              <Text mb="xs">
                This domain will be authorised for receiving subscription notifications.
              </Text>
              <Text mb="md">
                <strong>Note:</strong> All subscription notification URIs must use this registered
                domain, or they will be rejected.
              </Text>
              <TextInput
                value={domainValue}
                onChange={(e) => setDomainValue(e.target.value)}
                placeholder="Enter a FQDN (e.g. my.example.com)"
                mb="sm"
              />
              <Button
                leftSection={<IconPencil size={14} />}
                loading={domainMutation.isPending}
                onClick={() => domainMutation.mutate()}
              >
                Update Domain
              </Button>
            </Card>

            {/* DeviceCapability URI card */}
            <Card withBorder>
              <Title order={5} mb="xs">
                DeviceCapability URI
              </Title>
              <Text mb="xs">
                The DeviceCapability URI can be set to be either &quot;static&quot; or
                &quot;dynamic&quot; on a per run group basis.
              </Text>
              <Text mb="xs">
                A &quot;static&quot; value results in sharing the same DeviceCapability URI across
                all test runs in that run group. <strong>Note:</strong> when &quot;static&quot; is
                set only <em>one</em> test run can be active at any given time. A test must be
                started before these URIs will be active!
              </Text>
              <Text size="sm" c="dimmed">
                Use the <strong>Swap to static / dynamic</strong> control on each run group above to
                change this setting, then start a test run from the{' '}
                <Text component={Link} to="/runs" c="blue" inherit>
                  Runs
                </Text>{' '}
                page to activate the URI.
              </Text>
            </Card>
          </SimpleGrid>
        </Stack>
      )}
    </>
  );
}

function SharedCertMenu({ onCertAction }: { onCertAction: () => void }) {
  const [opened, { open, close }] = useDisclosure(false);

  const handleApply = () => {
    close();
    onCertAction();
  };

  return (
    <>
      <Menu>
        <Menu.Target>
          <Button variant="default">Advanced Options</Button>
        </Menu.Target>
        <Menu.Dropdown>
          <Menu.Item onClick={open}>Generate Shared Aggregator Certificate</Menu.Item>
        </Menu.Dropdown>
      </Menu>

      <Modal
        opened={opened}
        onClose={close}
        title="Generate Shared Aggregator Certificate"
        size="lg"
      >
        <Stack>
          <Text>
            A new aggregator certificate will be generated and set as the certificate for all run
            groups.
            <br />
            <br />
            <strong>Note:</strong> Generating a new aggregator certificate will replace <em>all</em>{' '}
            existing certificates for <em>all</em> run groups.
          </Text>
          <Group justify="flex-end">
            <form
              method="POST"
              action="/config/shared_cert"
              target="hiddenFrame-shared"
              onSubmit={handleApply}
              style={{ display: 'inline' }}
            >
              <Button
                type="submit"
                variant="outline"
                color="red"
                leftSection={<IconRecycle size={14} />}
              >
                Apply
              </Button>
            </form>
          </Group>
        </Stack>
        <iframe
          name="hiddenFrame-shared"
          style={{ display: 'none' }}
          title="shared-cert-download"
        />
      </Modal>
    </>
  );
}
