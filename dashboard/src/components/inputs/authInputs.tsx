import { FC } from 'react';
import { ErrorMessage, Field } from 'formik';

type AuthInputsProps = {
  name: string;
  type: string;
  placeholder: string;
};

export const AuthInputs: FC<AuthInputsProps> = ({
  name,
  type,
  placeholder,
}) => {
  return (
    <div className='w-full'>
      <Field
        name={name}
        type={type}
        placeholder={placeholder}
        className='w-full px-4 py-3 bg-white bg-opacity-10 border border-white border-opacity-20 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent text-white placeholder-white placeholder-opacity-60 transition-all duration-200 backdrop-blur-sm'
      />
      <ErrorMessage
        name={name}
        component='div'
        className='dark:text-red-400 text-red-900 text-sm mt-1 font-medium'
      />
    </div>
  );
};
