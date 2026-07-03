import { Heading, Link, Text } from '@radix-ui/themes';
import { useQuery } from '@tanstack/react-query';
import hljs from 'highlight.js/lib/core';
import yamlLanguage from 'highlight.js/lib/languages/yaml';
import { useParams } from 'react-router-dom';
import { fetchProcedureYaml } from '../api/procedures';
import { Banner } from '../components/Banner';
import { ErrorAlert } from '../components/ErrorAlert';
import { PageSpinner } from '../components/PageSpinner';
import { useDocumentTitle } from '../hooks/useDocumentTitle';
import { useSession } from '../hooks/useSession';
import 'highlight.js/styles/default.css';

hljs.registerLanguage('yaml', yamlLanguage);

export function ProcedureYamlPage() {
  useDocumentTitle('Procedures - CACTUS');
  const { testProcedureId = '' } = useParams();
  const { data: session } = useSession();
  const { data, isPending, error } = useQuery({
    queryKey: ['procedure', testProcedureId],
    queryFn: () => fetchProcedureYaml(testProcedureId),
  });

  return (
    <>
      <Banner message={session?.banner_message} />
      <Heading as="h2" size="6" mb="3">
        Test Procedure {testProcedureId}
      </Heading>

      <Text as="p" mb="3">
        The following test procedure is described and maintained at{' '}
        <Link href="https://github.com/bsgip/cactus-test-definitions">CACTUS Test Definitions</Link>{' '}
        repository
      </Text>

      {isPending ? (
        <PageSpinner />
      ) : error ? (
        <ErrorAlert message={error.message} />
      ) : (
        <pre>
          <code
            className="hljs language-yaml"
            dangerouslySetInnerHTML={{
              __html: hljs.highlight(data.yaml, { language: 'yaml' }).value,
            }}
          />
        </pre>
      )}
    </>
  );
}
