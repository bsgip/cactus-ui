import { Button, Code, Flex, Heading, Text } from '@radix-ui/themes';
import { Link as RouterLink, useLocation } from 'react-router-dom';

export function NotFoundPage() {
  const { pathname } = useLocation();

  return (
    <Flex direction="column" align="center" gap="3" py="9">
      <Heading size="9" weight="light" color="gray">
        404
      </Heading>
      <Heading as="h1" size="6">
        Page not found
      </Heading>
      <Text color="gray" align="center">
        There's no page at <Code>{pathname}</Code>. It may have been moved, or the link may be out
        of date.
      </Text>
      <Button asChild mt="2">
        <RouterLink to="/">Back to Home</RouterLink>
      </Button>
    </Flex>
  );
}
