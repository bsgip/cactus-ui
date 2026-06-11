import { Center, Loader } from '@mantine/core';

export function PageSpinner() {
  return (
    <Center py="xl">
      <Loader color="green" />
    </Center>
  );
}
