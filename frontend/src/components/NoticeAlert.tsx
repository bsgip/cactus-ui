import { Alert, AlertVariant } from './Alert';

function NoticeAlert({ message }: { message: string }) {
  return <Alert variant={AlertVariant.notice} message={message} />
}
export default NoticeAlert;
