import FieldHeader from './FieldHeader';

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
      <FieldHeader title={label}>
      {help}
      </FieldHeader>
      {children}
    </label>
  );
}

export default FormFieldGroup;


