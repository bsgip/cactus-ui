import { Callout } from '@radix-ui/themes';
import { IconAlertTriangle, IconCircleCheck } from '@tabler/icons-react';


export enum AlertVariant {
  error,
  notice
}

export function Alert({ message, variant }: { message: string, variant: AlertVariant }) {
  const alertIconSize = 16;
  let alertColor: 'red' | 'green';
  let alertRole: string;
  let alertIcon: React.ReactNode;
  switch (variant) {
    case AlertVariant.error:
      alertColor = 'red';
      alertRole = 'alert';
      alertIcon = <IconAlertTriangle size={alertIconSize} />;
      break;
    case AlertVariant.notice:
      alertColor = 'green';
      alertRole = 'status';
      alertIcon = <IconCircleCheck size={alertIconSize} />;
      break;
    default:
      return null;
  }
  return (
    <Callout.Root color={alertColor} role={alertRole} mb="3">
      <Callout.Icon>
        {alertIcon}
      </Callout.Icon>
      <Callout.Text>{message}</Callout.Text>
    </Callout.Root>
  );
}
