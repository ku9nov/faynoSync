import { useState } from 'react';
import * as Yup from 'yup';
import { useNavigate, useLocation } from 'react-router-dom';
import { Formik, Form } from 'formik';
import { AuthWrapper } from '@/components/auth-wrapper/authWrapper.tsx';
import { AuthLogo } from '@/components/auth-logo/authLogo.tsx';
import { AuthButton } from '@/components/buttons/authButton.tsx';
import { AuthInputs } from '@/components/inputs/authInputs.tsx';
import { useAuth } from '@/providers/authProvider.tsx';
import '@/styles/cards.css';

interface FormValues {
  username: string;
  password: string;
}

export const SignInPage = () => {
  const [respError, setRespError] = useState<string>('');
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const initialValues: FormValues = {
    username: '',
    password: '',
  };

  const validationSchema = Yup.object().shape({
    username: Yup.string()
      .min(3, 'Minimum 3 symbol')
      .required('Required field'),
    password: Yup.string()
      .min(6, 'Minimum 6 symbol')
      .required('Required field'),
  });

  const handleSubmit = async (e: FormValues) => {
    if (respError) {
      setRespError('');
    }
    try {
      await login({ username: e.username, password: e.password });
      // Use the 'from' state if available, otherwise default to '/applications'
      const from = location.state?.from || '/applications';
      navigate(from);
    } catch (error: any) {
      setRespError(error);
    }
  };

  return (
    <AuthWrapper>
      <div className='flex md:flex-row flex-col-reverse w-full'>
        <div className='w-full md:w-1/2 flex items-center justify-center p-8'>
          <div className='sharedCard sharedCard--auth w-full max-w-md'>
            {/* <div className='sharedCardIcon'>
              <i className='fas fa-sign-in-alt text-2xl text-white'></i>
            </div> */}
            <div className='sharedCardContent'>
              <h2 className='sharedCardTitle text-center mb-8'>
                Sign In
              </h2>
              <Formik
                initialValues={initialValues}
                validationSchema={validationSchema}
                onSubmit={(values: FormValues) => {
                  handleSubmit(values);
                }}>
                {({}) => (
                  <Form className='flex flex-col gap-5 w-full'>
                    <AuthInputs
                      name='username'
                      type='text'
                      placeholder='Username'
                    />
                    <AuthInputs
                      name='password'
                      type='Password'
                      placeholder='password'
                    />
                    <div className='w-full text-red-400 text-center text-sm'>
                      {respError && respError}
                    </div>
                    <div className='flex flex-col gap-4 mt-2'>
                      <AuthButton type='submit' text='Login' onClick={() => {}} />
                      <AuthButton
                        type='button'
                        text='Register'
                        onClick={() => {
                          navigate('/signup');
                        }}
                      />
                    </div>
                  </Form>
                )}
              </Formik>
            </div>
          </div>
        </div>
        <AuthLogo />
      </div>
    </AuthWrapper>
  );
};
