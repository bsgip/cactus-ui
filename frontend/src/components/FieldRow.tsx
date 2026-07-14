import { Text } from '@radix-ui/themes';

function FormFieldGroup({
  label,
  help,
  children,
}: {
  label: string;
  help?: string;
  children: React.ReactNode;
}) {
  return (
    <label>
      <Text as="div" size="2" weight="bold" mb="1">
        {label}
      </Text>
      {children}
      {help && (
        <Text as="div" size="1" color="gray" mt="1">
          {help}
        </Text>
      )}
    </label>
  );
}

export default FormFieldGroup;


