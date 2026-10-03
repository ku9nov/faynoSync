import { StepStatus, TaskState } from '@/components/settings/tuf/types';

export const getStatusColor = (status: StepStatus) => {
  switch (status) {
    case 'ready':
      return 'text-blue-500';
    case 'in-progress':
      return 'text-yellow-500';
    case 'success':
      return 'text-green-500';
    case 'error':
      return 'text-red-500';
    case 'waiting':
    case 'disabled':
    default:
      return 'text-gray-500';
  }
};

export const getStatusIcon = (status: StepStatus) => {
  switch (status) {
    case 'ready':
      return 'fa-circle';
    case 'in-progress':
      return 'fa-spinner fa-spin';
    case 'success':
      return 'fa-check-circle';
    case 'error':
      return 'fa-times-circle';
    case 'waiting':
      return 'fa-clock';
    case 'disabled':
    default:
      return 'fa-circle';
  }
};

export const getTaskStateColor = (state: TaskState) => {
  switch (state) {
    case 'SUCCESS':
      return 'text-green-500';
    case 'FAILURE':
      return 'text-red-500';
    case 'PENDING':
      return 'text-yellow-500';
    default:
      return 'text-gray-500';
  }
};
