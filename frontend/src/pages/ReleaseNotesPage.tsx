import { Badge, Box, Flex, Heading, Link, Table, Text } from '@radix-ui/themes';
import { useQuery } from '@tanstack/react-query';
import { Fragment, type ReactNode } from 'react';
import { fetchReleaseNotes } from '../api/releaseNotes';
import type { Release, ReleaseComponent } from '../api/types';
import { Alert, AlertVariant } from '../components/Alert';
import { CategoryAccordion } from '../components/CategoryAccordion';
import { ErrorAlert } from '../components/ErrorAlert';
import Page from '../components/Page';
import { PageSpinner } from '../components/PageSpinner';
import { useDocumentTitle } from '../hooks/useDocumentTitle';

const CACTUS_DEPLOY_RELEASES_URL = 'https://github.com/bsgip/cactus-deploy/releases';

function formatDateNoSeconds(d: Date): string {
  return d.toLocaleString('sv', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function ChangeList({ changes }: { changes: { title: string; pr: number; url: string }[] }) {
  return (
    <ul style={{ margin: 0, paddingLeft: '1.25em' }}>
      {changes.map((change) => (
        <li key={change.pr}>
          {change.title}{' '}
          <Link href={change.url} target="_blank" rel="noreferrer">
            (#{change.pr})
          </Link>
        </li>
      ))}
    </ul>
  );
}

const componentBlockStyle = {
  borderLeft: '3px solid var(--accent-6)',
  paddingLeft: 'var(--space-3)',
};

function ComponentBlock({ name, version, children }: { name: string; version: string; children?: ReactNode }) {
  return (
    <Box style={componentBlockStyle} py="1">
      <Flex gap="2" align="baseline" wrap="wrap" mb="1">
        <Heading as="h5" size="2">
          {name}
        </Heading>
        <Text size="1" color="gray">
          {version}
        </Text>
      </Flex>
      {children}
    </Box>
  );
}

function ComponentRow({ component }: { component: ReleaseComponent }) {
  return (
    <ComponentBlock name={component.name} version={`${component.previous ?? 'new'} → ${component.current}`}>
      {component.notes.map((note) => (
        <Alert key={note} variant={AlertVariant.notice} message={note} />
      ))}
      {component.changes.length > 0 && <ChangeList changes={component.changes} />}
    </ComponentBlock>
  );
}

function TestDefinitionsRow({ testDefinitions }: { testDefinitions: NonNullable<Release['test_definitions']> }) {
  return (
    <ComponentBlock name="Test Procedures" version={`${testDefinitions.previous} → ${testDefinitions.current}`}>
      {testDefinitions.procedures && (
        <Text as="p" size="2">
          {testDefinitions.procedures.modified} tests modified, {testDefinitions.procedures.added} added,{' '}
          {testDefinitions.procedures.removed} removed
          {testDefinitions.procedures.total !== null && ` (${testDefinitions.procedures.total} total)`}
        </Text>
      )}
      {testDefinitions.notes.map((note) => (
        <Alert key={note} variant={AlertVariant.notice} message={note} />
      ))}
      {testDefinitions.changes.length > 0 && <ChangeList changes={testDefinitions.changes} />}
    </ComponentBlock>
  );
}

function ReleaseCard({ release, defaultOpen }: { release: Release; defaultOpen: boolean }) {
  const changed = release.components.filter((c) => c.changed);
  const unchanged = release.components.filter((c) => !c.changed);

  return (
    <CategoryAccordion
      defaultOpen={defaultOpen}
      title={
        <Flex gap="3" align="center" wrap="wrap">
          <Text weight="bold">{release.tag}</Text>
          {release.deployed_at && (
            <Badge color="green">deployed {formatDateNoSeconds(new Date(release.deployed_at))}</Badge>
          )}
          <Text size="1" color="gray">
            {changed.length} repositories changed
          </Text>
        </Flex>
      }
    >
      <Box p="3">
        {release.warnings.map((warning) => (
          <Alert key={warning} variant={AlertVariant.error} message={warning} />
        ))}

        <Heading as="h4" size="3" mb="1">
          Repositories
        </Heading>
        <Flex direction="column" gap="3" mb="3">
          {release.test_definitions && <TestDefinitionsRow testDefinitions={release.test_definitions} />}
          {changed.map((c) => (
            <ComponentRow key={c.name} component={c} />
          ))}
        </Flex>

        {unchanged.length > 0 && (
          <details style={{ marginBottom: 'var(--space-4)' }}>
            <summary style={{ color: 'var(--gray-9)', fontSize: 'var(--font-size-1)' }}>
              {unchanged.length} repositories unchanged
            </summary>
            <Table.Root size="1" mt="2">
              <Table.Header>
                <Table.Row>
                  <Table.ColumnHeaderCell>Repository</Table.ColumnHeaderCell>
                  <Table.ColumnHeaderCell>Version</Table.ColumnHeaderCell>
                </Table.Row>
              </Table.Header>
              <Table.Body>
                {unchanged.map((c) => (
                  <Table.Row key={c.name}>
                    <Table.RowHeaderCell>{c.name}</Table.RowHeaderCell>
                    <Table.Cell>{c.current}</Table.Cell>
                  </Table.Row>
                ))}
              </Table.Body>
            </Table.Root>
          </details>
        )}
      </Box>
    </CategoryAccordion>
  );
}

export function ReleaseNotesPage() {
  useDocumentTitle('Release Notes - CACTUS');
  const query = useQuery({
    queryKey: ['release-notes'],
    queryFn: fetchReleaseNotes,
  });

  const releases = query.data?.releases ?? [];

  return (
    <Page title="Release Notes">
      <Text as="p" size="2" mb="4">
        <Link href={CACTUS_DEPLOY_RELEASES_URL} target="_blank" rel="noreferrer">
          View all releases on GitHub
        </Link>
      </Text>
      {query.isPending ? (
        <PageSpinner />
      ) : query.error ? (
        <ErrorAlert message="Failed to fetch release notes." />
      ) : releases.length === 0 ? (
        <Text as="p" color="gray">
          No release notes to show yet.{' '}
          <Link href={CACTUS_DEPLOY_RELEASES_URL} target="_blank" rel="noreferrer">
            View releases on GitHub
          </Link>
          .
        </Text>
      ) : (
        <Fragment>
          {releases.map((release, i) => (
            <ReleaseCard key={release.tag} release={release} defaultOpen={i === 0} />
          ))}
        </Fragment>
      )}
    </Page>
  );
}
