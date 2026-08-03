import {Alert, AlertVariant} from './Alert';

export function ErrorAlert({ message }: { message: string }) {
  return <Alert variant={AlertVariant.error} message={message} />
}

