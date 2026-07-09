import { Button, Flex, Text, Tooltip } from '@radix-ui/themes';
import { IconCertificate } from '@tabler/icons-react';
import { useMutation } from '@tanstack/react-query';
import { generateSharedCert } from '../../api/config';
import { ModalButton } from '../../components/ModalButton';

// First-class action that mints a single aggregator certificate and assigns it to *all* of the
// user's run groups - the "one aggregator identity for the whole organisation" flow. Disabled until
// a notification domain is set, since an aggregator certificate bakes that domain into its SAN.
export function SharedCertButton({
  hasDomain,
  onCertAction,
  onCertError,
}: {
  hasDomain: boolean;
  onCertAction: (message: string) => void;
  onCertError: (message: string) => void;
}) {
  const generateMutation = useMutation({ mutationFn: generateSharedCert });

  return (
    <ModalButton
      title="Generate Aggregator Certificate for All Groups"
      size="lg"
      trigger={(open) =>
        hasDomain ? (
          <Button variant="soft" onClick={open}>
            <IconCertificate size={14} />
            Aggregator cert for all groups
          </Button>
        ) : (
          <Tooltip content="Set a notification domain first - an aggregator certificate requires it.">
            <Button variant="soft" disabled>
              <IconCertificate size={14} />
              Aggregator cert for all groups
            </Button>
          </Tooltip>
        )
      }
    >
      {(close) => {
        const handleApply = () => {
          generateMutation.mutate(undefined, {
            onSuccess: () => {
              close();
              onCertAction(
                'Aggregator certificate generated and applied to all run groups — download starting.'
              );
            },
            onError: (err) => {
              close();
              onCertError(err.message);
            },
          });
        };
        return (
          <Flex direction="column" gap="3">
            <Text>
              This mints <em>one</em> aggregator certificate - representing a single organisation
              identity - and assigns it to <em>all</em> of your run groups.
              <br />
              <br />
              <strong>Note:</strong> this replaces the existing certificate on <em>every</em> run
              group. Use the per-group options instead if you need different certificates for
              different groups.
            </Text>
            <Flex justify="end">
              <Button
                variant="outline"
                color="red"
                loading={generateMutation.isPending}
                onClick={handleApply}
              >
                <IconCertificate size={14} />
                Generate &amp; apply to all groups
              </Button>
            </Flex>
          </Flex>
        );
      }}
    </ModalButton>
  );
}
