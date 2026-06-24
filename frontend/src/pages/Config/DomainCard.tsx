import { Button, Text, TextInput } from '@mantine/core';
import { IconPencil } from '@tabler/icons-react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { updateDomain } from '../../api/config';
import { SectionCard } from '../../components/SectionCard';

export function DomainCard({
  domain,
  setError,
}: {
  domain: string;
  setError: (msg: string | null) => void;
}) {
  const queryClient = useQueryClient();
  const [domainValue, setDomainValue] = useState(domain);

  const mutation = useMutation({
    mutationFn: () => updateDomain(domainValue),
    onSuccess: () => {
      setError(null);
      void queryClient.invalidateQueries({ queryKey: ['config'] });
    },
    onError: (err: Error) => setError(err.message),
  });

  return (
    <SectionCard title="Subscription Notification Domain (Optional)">
      <Text mb="xs">
        This domain will be authorised for receiving subscription notifications.
      </Text>
      <Text mb="md">
        <strong>Note:</strong> All subscription notification URIs must use this registered domain,
        or they will be rejected.
      </Text>
      <TextInput
        value={domainValue}
        onChange={(e) => setDomainValue(e.target.value)}
        placeholder="Enter a FQDN (e.g. my.example.com)"
        mb="sm"
      />
      <Button
        leftSection={<IconPencil size={14} />}
        loading={mutation.isPending}
        onClick={() => mutation.mutate()}
      >
        Update Domain
      </Button>
    </SectionCard>
  );
}
