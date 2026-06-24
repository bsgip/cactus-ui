import { Code, Loader, Modal, Text, Title } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { fetchRequestDetails } from '../../api/runStatus';

interface Props {
  runId: number;
  requestId: number | null;
  onClose: () => void;
}

// Shared request/response detail modal, opened from both the CSIP-Aus Requests table and the
// XSD Validation Errors panel. Uses the user-path endpoint even in the admin view.
export function RequestDetailsModal({ runId, requestId, onClose }: Props) {
  const query = useQuery({
    queryKey: ['run_request_details', runId, requestId],
    queryFn: () => fetchRequestDetails(runId, requestId as number),
    enabled: requestId !== null,
  });

  const firstLine = query.data?.request?.split('\n')[0].trim() || 'Request';

  return (
    <Modal opened={requestId !== null} onClose={onClose} title={firstLine} size="xl">
      {query.isPending ? (
        <Loader />
      ) : query.error ? (
        <Text c="red">Failed to load request details</Text>
      ) : (
        <>
          <Title order={6} mb={4}>
            Request
          </Title>
          <Code block mb="md">
            {query.data?.request || 'No request data'}
          </Code>
          <Title order={6} mb={4}>
            Response
          </Title>
          <Code block>{query.data?.response || 'No response data'}</Code>
        </>
      )}
    </Modal>
  );
}
