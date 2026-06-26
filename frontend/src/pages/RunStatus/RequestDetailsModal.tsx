import { Code, Dialog, Heading, Spinner, Text } from '@radix-ui/themes';
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
    <Dialog.Root open={requestId !== null} onOpenChange={(open) => !open && onClose()}>
      <Dialog.Content maxWidth="800px">
        <Dialog.Title>{firstLine}</Dialog.Title>
        {query.isPending ? (
          <Spinner />
        ) : query.error ? (
          <Text color="red">Failed to load request details</Text>
        ) : (
          <>
            <Heading as="h6" size="2" mb="1">
              Request
            </Heading>
            <Code variant="soft" mb="3" style={{ display: 'block', whiteSpace: 'pre-wrap' }}>
              {query.data?.request || 'No request data'}
            </Code>
            <Heading as="h6" size="2" mb="1">
              Response
            </Heading>
            <Code variant="soft" style={{ display: 'block', whiteSpace: 'pre-wrap' }}>
              {query.data?.response || 'No response data'}
            </Code>
          </>
        )}
      </Dialog.Content>
    </Dialog.Root>
  );
}
