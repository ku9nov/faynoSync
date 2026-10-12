import { toast, ToastOptions } from 'react-toastify';

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

// Module-level so the functions keep their identity across renders and are safe in hook deps
export const useToast = () => ({ toastSuccess, toastError, toastWarn, toastInfo });
