import styled from 'styled-components';

const SpinnerContainer = styled.div`
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100vh;
  background: linear-gradient(135deg, var(--bg-gradient-start), var(--bg-gradient-end));
`;

const Spinner = styled.div`
  width: 50px;
  height: 50px;
  border: 3px solid rgba(255, 255, 255, 0.1);
  border-top: 3px solid var(--text-primary);
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin-bottom: 20px;

  @keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
  }
`;

const LoadingText = styled.div`
  color: var(--text-primary);
  font-size: 16px;
  font-weight: 500;
`;

export const LoadingSpinner = () => {
  return (
    <SpinnerContainer>
      <Spinner />
      <LoadingText>Loading...</LoadingText>
    </SpinnerContainer>
  );
}; 