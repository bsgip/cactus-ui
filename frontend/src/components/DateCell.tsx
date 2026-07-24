import { Text } from '@radix-ui/themes';

import { formatDate, formatRelativeDate } from '../utils/dates';

function DateCell({ value }: { value: string }) {
  const date = new Date(value);
  return (
    <>
      {formatDate(date)}
      <br />
      <Text size="1" color="gray">
        ({formatRelativeDate(date)})
      </Text>
    </>
  );
}


export default DateCell;
