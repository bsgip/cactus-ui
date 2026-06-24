import { Button, NumberInput, Text } from '@mantine/core';
import { IconPencil } from '@tabler/icons-react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { updatePen } from '../../api/config';
import { SectionCard } from '../../components/SectionCard';

export function PenCard({
  pen,
  setError,
}: {
  pen: number | null;
  setError: (msg: string | null) => void;
}) {
  const queryClient = useQueryClient();
  const [penValue, setPenValue] = useState<string | number>(pen ?? '');

  const mutation = useMutation({
    mutationFn: () => updatePen(Number(penValue)),
    onSuccess: () => {
      setError(null);
      void queryClient.invalidateQueries({ queryKey: ['config'] });
    },
    onError: (err: Error) => setError(err.message),
  });

  return (
    <SectionCard title="Private Enterprise Number (PEN)">
      <Text mb="xs">
        A Private Enterprise Number (PEN) is a numeric identifier for an organisation, individual or
        other entity. CSIP-Aus requires clients to encode a PEN within various requests to the
        server.
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
        loading={mutation.isPending}
        onClick={() => mutation.mutate()}
      >
        Update PEN
      </Button>
    </SectionCard>
  );
}
