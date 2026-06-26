import { Button, Text, TextField } from '@radix-ui/themes';
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
      <Text as="p" mb="1">
        This domain will be authorised for receiving subscription notifications.
      </Text>
      <Text as="p" mb="3">
        <strong>Note:</strong> All subscription notification URIs must use this registered domain,
        or they will be rejected.
      </Text>
      <TextField.Root
        value={domainValue}
        onChange={(e) => setDomainValue(e.target.value)}
        placeholder="Enter a FQDN (e.g. my.example.com)"
        mb="2"
      />
      <Button loading={mutation.isPending} onClick={() => mutation.mutate()}>
        <IconPencil size={14} />
        Update Domain
      </Button>
    </SectionCard>
  );
}
