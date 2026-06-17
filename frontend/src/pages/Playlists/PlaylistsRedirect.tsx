import { useQuery } from '@tanstack/react-query';
import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { fetchRunGroups } from '../../api/runs';
import { ErrorAlert } from '../../components/ErrorAlert';
import { PageSpinner } from '../../components/PageSpinner';

// Port of the playlists_page Flask route: /playlists redirects to the first run group's
// playlists page, or to the (still Flask-rendered) config page when there are none.
export function PlaylistsRedirect() {
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
      void navigate(`/group/${data.items[0].run_group_id}/playlists`, { replace: true });
    } else {
      window.location.assign('/config');
    }
  }, [data, navigate]);

  if (error) {
    return <ErrorAlert message="Unable to fetch run groups." />;
  }
  return <PageSpinner />;
}
