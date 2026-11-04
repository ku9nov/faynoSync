import { useEffect, useState } from 'react';
import { isRouteErrorResponse, useRouteError } from 'react-router-dom';
import styled from 'styled-components';
import { LoadingSpinner } from '@/components/LoadingSpinner';

// Chrome, Firefox, Safari and Vite's CSS preload wording for a lazy chunk that no longer exists after a redeploy
const staleChunkPattern = /dynamically imported module|Importing a module script failed|Unable to preload CSS/i;
const reloadKey = 'staleChunkReloadFor';

const staleChunkMessage = (error: unknown) =>
  error instanceof Error && staleChunkPattern.test(error.message) ? error.message : '';

// One reload per failing chunk: the message names the chunk URL, so a chunk still missing after
// the reload stops here regardless of how long the reload took, while a later deploy can reload again.
const shouldReload = (message: string) => {
  try {
    if (sessionStorage.getItem(reloadKey) === message) return false;
    sessionStorage.setItem(reloadKey, message);
    return true;
  } catch {
    return false;
  }
};

const Container = styled.div`
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 16px;
  height: 100vh;
  padding: 0 16px;
  text-align: center;
  color: var(--text-primary);
  background: linear-gradient(135deg, var(--bg-gradient-start), var(--bg-gradient-end));
`;

const Title = styled.h1`
  font-size: 24px;
  font-weight: 700;
`;

const Message = styled.p`
  max-width: 560px;
  opacity: 0.8;
  word-break: break-word;
`;

const ReloadButton = styled.button`
  padding: 10px 24px;
  border-radius: 8px;
  border: 1px solid var(--text-primary);
  color: var(--text-primary);
  background: transparent;
  font-weight: 600;
  cursor: pointer;
`;

export const RouteError = () => {
  const error = useRouteError();
  const staleMessage = staleChunkMessage(error);
  const stale = staleMessage !== '';
  const [reloadSkipped, setReloadSkipped] = useState(false);

  useEffect(() => {
    if (!staleMessage) return;
    if (shouldReload(staleMessage)) window.location.reload();
    else setReloadSkipped(true);
  }, [staleMessage]);

  if (stale && !reloadSkipped) return <LoadingSpinner />;

  const message = stale
    ? 'A new version of the dashboard was deployed. Reload the page to continue.'
    : isRouteErrorResponse(error)
      ? `${error.status} ${error.statusText}`
      : error instanceof Error
        ? error.message
        : 'Unexpected error';

  return (
    <Container>
      <Title>{stale ? 'Dashboard updated' : 'Something went wrong'}</Title>
      <Message>{message}</Message>
      <ReloadButton onClick={() => window.location.reload()}>Reload</ReloadButton>
    </Container>
  );
};
