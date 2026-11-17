import axios, { AxiosError } from 'axios';
import { env } from '@/config/env';

const axiosInstance = axios.create({
  baseURL: env.API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

axiosInstance.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

axiosInstance.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      window.location.href = `${import.meta.env.BASE_URL}signin`;
    }
    return Promise.reject(error);
  }
);

export type ApiError = AxiosError<{ error?: string; message?: string }>;

export const apiErrorMessage = (error: unknown, fallback: string): string => {
  const apiError = error as ApiError | undefined;
  return apiError?.response?.data?.error || apiError?.response?.data?.message || apiError?.message || fallback;
};

export default axiosInstance; 