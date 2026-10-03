import { useState } from 'react';
import * as Yup from 'yup';
import { useNavigate } from 'react-router-dom';
import { Form, Formik, FormikHelpers } from 'formik';
import { AuthWrapper } from '@/components/auth-wrapper/authWrapper.tsx';
import { AuthInputs } from '@/components/inputs/authInputs.tsx';
import { AuthButton } from '@/components/buttons/authButton.tsx';
import { useToast } from '@/hooks/useToast.ts';
import { AuthLogo } from '@/components/auth-logo/authLogo.tsx';
import { useAuth } from '@/providers/authProvider.tsx';
import '@/styles/cards.css';

interface FormValues {
  username: string;
  password: string;
  confirmPassword: string;
  secretKey: string;
}

export const SignUpPage = () => {
  const navigate = useNavigate();
  const { signUp } = useAuth();
  const { toastSuccess } = useToast();
  const [respError, setRespError] = useState<string>('');

  const initialValues: FormValues = {
    username: '',
    password: '',
    confirmPassword: '',
    secretKey: '',
  };

  const validationSchema = Yup.object().shape({
    username: Yup.string()
      .min(3, 'Minimum 3 symbol')
      .required('Required field'),
    password: Yup.string()
      .min(6, 'Minimum 6 symbol')
      .required('Required field'),
    confirmPassword: Yup.string()
      .oneOf([Yup.ref('password')], 'Passwords must match')
      .required('Required field'),
    secretKey: Yup.string().required('Required field'),
  });

  const handleSubmit = async (
    e: FormValues,
    formikHelpers: FormikHelpers<FormValues>
  ) => {
    const { resetForm } = formikHelpers;
    try {
      await signUp({
        username: e.username,
        password: e.password,
        secretKey: e.secretKey,
      });
      toastSuccess('Signed Up successfully.');
      navigate('/applications');
      resetForm();
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
              <i className='fas fa-user-plus text-2xl text-white'></i>
            </div> */}
            <div className='sharedCardContent'>
              <h2 className='sharedCardTitle text-center mb-8'>
                Register
              </h2>
              <Formik
                initialValues={initialValues}
                validationSchema={validationSchema}
                onSubmit={(
                  values: FormValues,
                  formikHelpers: FormikHelpers<FormValues>
                ) => {
                  handleSubmit(values, formikHelpers);
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
                    <AuthInputs
                      name='confirmPassword'
                      type='password'
                      placeholder='Confirm Password'
                    />
                    <AuthInputs
                      name='secretKey'
                      type='password'
                      placeholder='secretKey'
                    />
                    <div className='w-full text-red-400 text-center text-sm'>
                      {respError && respError}
                    </div>
                    <div className='flex flex-col gap-4 mt-2'>
                      <AuthButton
                        type='submit'
                        text='Register'
                        onClick={() => {}}
                      />
                      <AuthButton
                        type='button'
                        text='Login'
                        onClick={() => {
                          navigate('/signin');
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
