import { useMutation } from '@tanstack/react-query';

// useMutation wrapper that keeps the call sites terse (this page fires several near-identical mutations).
function useMutationSafe(
  fn: () => Promise<unknown>,
  onSuccess: () => void,
  onError: (e: Error) => void
) {
  return useMutation({ mutationFn: fn, onSuccess, onError });
}

export default useMutationSafe;
