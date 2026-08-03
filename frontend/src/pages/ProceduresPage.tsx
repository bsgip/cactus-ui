import { useQuery } from '@tanstack/react-query';

import { fetchProcedures } from '../api/procedures';
import { ErrorAlert } from '../components/ErrorAlert';
import { PageSpinner } from '../components/PageSpinner';
import { useDocumentTitle } from '../hooks/useDocumentTitle';
import Page from '../components/Page';
import ProceduresTable from '../components/ProceduresTable';


export function ProceduresPage() {
  useDocumentTitle('Procedures - CACTUS');

  const { data, isPending, error } = useQuery({
    queryKey: ['procedures'],
    queryFn: fetchProcedures,
  });

  return (
    <Page title="Test Procedures" includeBanner={true} >
      <>
        {isPending ? (
          <PageSpinner />
        ) : error ? (
          <ErrorAlert message="Failed to retrieve procedures." />
        ) : (
          <ProceduresTable data={data}/>
       )}
      </>
    </Page >
  );
}
