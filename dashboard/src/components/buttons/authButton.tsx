import { FC } from 'react';

type AuthButtonProps = {
  text: string;
  onClick: () => void;
  type?: 'submit' | 'button';
};

export const AuthButton: FC<AuthButtonProps> = ({
  text,
  onClick,
  type = 'submit',
}) => {
  return (
    <button
      type={type}
      onClick={onClick}
      className='w-full bg-purple-600 hover:bg-purple-700 text-white px-6 py-3 rounded-lg font-medium transition-all duration-200 transform hover:scale-105 hover:shadow-lg focus:outline-none focus:ring-2 focus:ring-purple-500 focus:ring-offset-2 focus:ring-offset-transparent'>
      {text}
    </button>
  );
};
