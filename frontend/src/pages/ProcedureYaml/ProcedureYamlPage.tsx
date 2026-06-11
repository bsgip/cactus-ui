import { Anchor, Text, Title } from '@mantine/core';
import { useDocumentTitle } from '@mantine/hooks';
import { useQuery } from '@tanstack/react-query';
import hljs from 'highlight.js/lib/core';
import yamlLanguage from 'highlight.js/lib/languages/yaml';
import { useParams } from 'react-router-dom';
import { fetchProcedureYaml } from '../../api/procedures';
import { Banner } from '../../components/Banner';
import { ErrorAlert } from '../../components/ErrorAlert';
import { PageSpinner } from '../../components/PageSpinner';
import { useSession } from '../../hooks/useSession';
import 'highlight.js/styles/default.css';

hljs.registerLanguage('yaml', yamlLanguage);

// Port of procedure_yaml.html.
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
      <Title order={2} mb="md">
        Test Procedure {testProcedureId}
      </Title>

      <Text mb="md">
        The following test procedure is described and maintained at{' '}
        <Anchor href="https://github.com/bsgip/cactus-test-definitions">
          CACTUS Test Definitions
        </Anchor>{' '}
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
