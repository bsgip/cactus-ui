import { useQuery } from '@tanstack/react-query';
import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { fetchRunGroups } from '../../api/runs';
import { ErrorAlert } from '../../components/ErrorAlert';
import { PageSpinner } from '../../components/PageSpinner';

// Port of the runs_page Flask route: /runs redirects to the first run group's runs
// page, or to the (still Flask-rendered) config page when there are no run groups.
export function RunsRedirect() {
  const navigate = useNavigate();
  const { data, error } = useQuery({
    queryKey: ['run_groups', 'mine'],
    queryFn: () => fetchRunGroups(false),
  });

  useEffect(() => {
    if (!data) {
      return;
    }
    if (data.items.length > 0) {
      void navigate(`/group/${data.items[0].run_group_id}/runs`, { replace: true });
    } else {
      window.location.assign('/config');
    }
  }, [data, navigate]);

  if (error) {
    return <ErrorAlert message="Unable to fetch run groups." />;
  }
  return <PageSpinner />;
}
