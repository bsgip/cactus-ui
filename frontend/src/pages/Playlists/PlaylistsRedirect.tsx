import { useQuery } from '@tanstack/react-query';
import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { fetchRunGroups } from '../../api/runs';
import { ErrorAlert } from '../../components/ErrorAlert';
import { PageSpinner } from '../../components/PageSpinner';

// /playlists redirects to the first run group's playlists page, or to the config page when
// the user has no run groups yet.
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
    const target =
      data.items.length > 0 ? `/group/${data.items[0].run_group_id}/playlists` : '/config';
    void navigate(target, { replace: true });
  }, [data, navigate]);

  if (error) {
    return <ErrorAlert message="Unable to fetch run groups." />;
  }
  return <PageSpinner />;
}
