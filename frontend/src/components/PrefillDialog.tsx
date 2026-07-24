
import {
  Button,
  Dialog,
  Flex,
  Select,
  Text,
} from '@radix-ui/themes';
import { IconPlus } from '@tabler/icons-react';
import { Link as RouterLink } from 'react-router-dom';
import type { ComplianceRequestResponse } from '../api/types';

interface PrefillDialogProps {
  prefillId: string;
  setPrefillId: (id: string) => void;
  requests: ComplianceRequestResponse[];
  target: string;
}

function PrefillDialog({prefillId, setPrefillId, requests, target}: PrefillDialogProps) {
  return (
    <Dialog.Root>
      <Dialog.Trigger>
        <Button size="3">
          <IconPlus size={16} /> New Request
        </Button>
      </Dialog.Trigger>
      <Dialog.Content maxWidth="500px">
        <Dialog.Title>New request for compliance</Dialog.Title>
        <Dialog.Description size="2" mb="3">
          To save time, a new compliance request can be pre-filled with the details (DER, software
          client) of an existing request. Classes and runs are not copied.
        </Dialog.Description>
        <Text as="label" size="2" weight="bold">
          Pre-fill from
        </Text>
        <Select.Root value={prefillId} onValueChange={setPrefillId}>
          <Select.Trigger placeholder="No pre-fill" mt="1" />
          <Select.Content>
            <Select.Item value="none">No pre-fill</Select.Item>
            {requests.map((r) => (
              <Select.Item key={r.compliance_request_id} value={String(r.compliance_request_id)}>
                Compliance Request #{r.compliance_request_id}
              </Select.Item>
            ))}
          </Select.Content>
        </Select.Root>
        <Flex gap="3" mt="4" justify="end">
          <Dialog.Close>
            <Button variant="soft" color="gray">
              Cancel
            </Button>
          </Dialog.Close>
          <Button asChild>
            <RouterLink to={target}>{prefillId ? 'Pre-fill request' : 'Continue'}</RouterLink>
          </Button>
        </Flex>
      </Dialog.Content>
    </Dialog.Root>
  );
}

export default PrefillDialog;
