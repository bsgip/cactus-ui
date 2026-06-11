import { useQuery } from '@tanstack/react-query';
import { fetchSession } from '../api/session';

export function useSession() {
  return useQuery({
    queryKey: ['session'],
    queryFn: fetchSession,
    retry: false,
    staleTime: 5 * 60 * 1000,
  });
}
