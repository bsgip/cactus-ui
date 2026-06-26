import { Button, Link, Text, TextField } from '@radix-ui/themes';
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
  const [penValue, setPenValue] = useState<string>(pen != null ? String(pen) : '');

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
      <Text as="p" mb="1">
        A Private Enterprise Number (PEN) is a numeric identifier for an organisation, individual or
        other entity. CSIP-Aus requires clients to encode a PEN within various requests to the
        server.
      </Text>
      <Text as="p" mb="3">
        A PEN can be obtained from <Link href="https://www.iana.org/">IANA</Link> for free from the
        following <Link href="https://www.iana.org/assignments/enterprise-numbers/">link</Link>.
      </Text>
      <TextField.Root
        type="number"
        min={1}
        max={4294967295}
        value={penValue}
        onChange={(e) => setPenValue(e.target.value)}
        placeholder="Enter PEN (e.g. 123456)"
        mb="2"
      />
      <Button loading={mutation.isPending} onClick={() => mutation.mutate()}>
        <IconPencil size={14} />
        Update PEN
      </Button>
    </SectionCard>
  );
}
