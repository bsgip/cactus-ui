import { Banner } from '../components/Banner';
import { useSession } from '../hooks/useSession';

function PageBanner() {
  const { data: session } = useSession();
  return (
      <Banner message={session?.banner_message} />
  );
}

export default PageBanner;
