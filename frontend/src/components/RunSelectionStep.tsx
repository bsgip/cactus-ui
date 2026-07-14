import {
  Badge,
  Button,
  Callout,
  Checkbox,
  Flex,
  Heading,
  Link,
  Select,
  Table,
  Text,
  Tooltip,
} from '@radix-ui/themes';
import { IconAlertTriangle } from '@tabler/icons-react';
import { useMemo } from 'react';
import { Link as RouterLink } from 'react-router-dom';
import { FormState } from '../utils/complianceRequestWizard';
import type {
  ComplianceFormDataResponse,
  RunResponse,
} from '../api/types';

function activeClassesEmpty(form: FormState, classesForVersion: string[]): boolean {
	return !classesForVersion.some((c) => form.classes.has(c));
}

interface RunSelectionStepProps {
  form: FormState;
  readOnly: boolean;
  formData: ComplianceFormDataResponse;
  classesForVersion: string[];
  visibleProcedures: string[];
  runsByProcedure: Record<string, RunResponse[]>;
  missingByClass: Record<string, string[]>;
  missingCount: number;
  toggleClass: (c: string, checked: boolean) => void;
  setAllClasses: (checked: boolean) => void;
  update: (patch: Partial<FormState>) => void;
  isAdminView: boolean;
}

function RunSelectionStep({
  form,
  readOnly,
  formData,
  classesForVersion,
  visibleProcedures,
  runsByProcedure,
  missingByClass,
  missingCount,
  toggleClass,
  setAllClasses,
  update,
  isAdminView,
}: RunSelectionStepProps) {
  const descriptions = useMemo(
    () => new Map(formData.compliance_classes.map((c) => [c.name, c.description])),
    [formData.compliance_classes]
  );


  return (
    <Flex direction="column" gap="4" pt="4">
      <Flex direction="column" gap="2">
        <Heading as="h3" size="4">
          Classes
        </Heading>
        <Text size="2">Choose all the compliance classes you want to be assessed under.</Text>
        {!readOnly && (
          <Flex gap="2">
            <Button size="1" onClick={() => setAllClasses(true)}>
              Select All
            </Button>
            <Button size="1" variant="soft" color="gray" onClick={() => setAllClasses(false)}>
              Deselect All
            </Button>
          </Flex>
        )}
        <Flex gap="3" wrap="wrap" mt="1">
          {classesForVersion.map((c) => (
            <Tooltip key={c} content={descriptions.get(c) || c}>
              <Text as="label" size="2" style={{ minWidth: 180 }}>
                <Flex gap="2" align="center">
                  <Checkbox
                    checked={form.classes.has(c)}
                    onCheckedChange={(checked) => toggleClass(c, checked === true)}
                    disabled={readOnly}
                  />
                  {c}
                </Flex>
              </Text>
            </Tooltip>
          ))}
        </Flex>
      </Flex>

      {missingCount > 0 && (
        <Callout.Root color="red">
          <Callout.Icon>
            <IconAlertTriangle size={16} />
          </Callout.Icon>
          <Callout.Text>
            <Text as="div" weight="bold" mb="1">
              Runs Missing
            </Text>
            Some chosen compliance classes do not have successful test runs:
            <ul style={{ margin: '8px 0' }}>
              {Object.entries(missingByClass).map(([c, missing]) => (
                <li key={c}>
                  <strong>Class {c}:</strong> {missing.join(', ')}
                </li>
              ))}
            </ul>
            There is a total of <strong>{missingCount}</strong> missing runs. You must complete the
            required tests or remove the incomplete classes before{' '}
            {isAdminView ? 'finalising' : 'submitting'}.
          </Callout.Text>
        </Callout.Root>
      )}

      {visibleProcedures.length > 0 && (
        <Flex direction="column" gap="2">
          <Heading as="h3" size="4">
            Runs
          </Heading>
          <Text size="2">
            For each test procedure, choose which run you want assessed. Only successful (finalised
            and passing) runs are shown.
          </Text>
          <Table.Root variant="surface">
            <Table.Body>
              {visibleProcedures.map((p) => (
                <Table.Row key={p}>
                  <Table.RowHeaderCell>
                    <Link asChild>
                      <RouterLink to={`/procedure/${p}`}>{p}</RouterLink>
                    </Link>
                  </Table.RowHeaderCell>
                  <Table.Cell>
                    <Select.Root
                      value={form.runByProcedure[p] ? String(form.runByProcedure[p]) : undefined}
                      onValueChange={(v) =>
                        update({ runByProcedure: { ...form.runByProcedure, [p]: Number(v) } })
                      }
                      disabled={readOnly}
                    >
                      <Select.Trigger placeholder="Select a run" />
                      <Select.Content>
                        {(runsByProcedure[p] ?? []).map((run) => (
                          <Select.Item key={run.run_id} value={String(run.run_id)}>
                            #{run.run_id}
                          </Select.Item>
                        ))}
                      </Select.Content>
                    </Select.Root>
                  </Table.Cell>
                  <Table.Cell>
                    {form.runByProcedure[p] && (
                      <Link asChild>
                        <RouterLink to={`/run/${form.runByProcedure[p]}`}>View</RouterLink>
                      </Link>
                    )}
                  </Table.Cell>
                </Table.Row>
              ))}
            </Table.Body>
          </Table.Root>
        </Flex>
      )}
      {activeClassesEmpty(form, classesForVersion) && (
        <Badge color="gray">Select at least one compliance class to choose runs.</Badge>
      )}
    </Flex>
  );
}

export default RunSelectionStep;
