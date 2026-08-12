import { Text } from '@radix-ui/themes';

function FormFieldGroup({
  label,
  help,
  children,
}: {
  label: string;
  help?: string | React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <label>
      <Text as="div" size="2" weight="bold" mb="1">
        {label}
      </Text>
      {children}
      {typeof help==="string" && (
        <Text as="div" size="1" color="gray" mt="1">
          {help}
        </Text>
      )}
      {typeof help==="object" && help}
    </label>
  );
}

export default FormFieldGroup;


