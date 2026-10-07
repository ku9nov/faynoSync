import { toast, ToastOptions } from 'react-toastify';

export const useToast = () => {
  const options: ToastOptions = {
    position: 'top-right',
    autoClose: 3000,
    hideProgressBar: false,
    closeOnClick: true,
    pauseOnHover: true,
  };

  const toastSuccess = (message: string) => {
    toast.success(message, options);
  };

  const toastError = (message: string) => {
    toast.error(message, options);
  };

  const toastWarn = (message: string) => {
    toast.success(message, options);
  };

  const toastInfo = (message: string) => {
    toast.success(message, options);
  };

  return { toastSuccess, toastError, toastWarn, toastInfo };
};
