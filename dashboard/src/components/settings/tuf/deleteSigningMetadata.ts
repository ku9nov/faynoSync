import axiosInstance from '@/config/axios';

export interface DeleteSigningMetadataParams {
  appName: string;
  role: string;
}

export interface DeleteSigningMetadataResponse {
  message?: string;
  data?: {
    task_id?: string;
    last_update?: string;
  };
  error?: string;
}

export interface DeleteSigningMetadataResult {
  success: boolean;
  hasTask: boolean;
  message: string;
  taskId?: string;
  lastUpdate?: string;
  error?: string;
}

/**
 * Delete signing metadata for a specific role
 * @param params - Parameters containing appName and role
 * @returns Promise with the result containing success status, task info, and message
 */
export const deleteSigningMetadata = async (
  params: DeleteSigningMetadataParams
): Promise<DeleteSigningMetadataResult> => {
  const { appName, role } = params;

  if (!appName) {
    throw new Error('App name is required');
  }

  if (!role) {
    throw new Error('Role is required');
  }

  try {
    const response = await axiosInstance.post(
      `/tuf/v1/metadata/sign/delete?appName=${encodeURIComponent(appName)}`,
      {
        role,
      }
    );

    const responseData: DeleteSigningMetadataResponse = response.data;
    
    // Check if we have a task_id (successful deletion with task)
    if (responseData.data?.task_id) {
      return {
        success: true,
        hasTask: true,
        message: responseData.message || 'Metadata sign delete accepted.',
        taskId: responseData.data.task_id,
        lastUpdate: responseData.data.last_update,
      };
    }
    
    // If no task_id but we got a response, it might be a success without task
    return {
      success: true,
      hasTask: false,
      message: responseData.message || 'Signing metadata deleted successfully.',
    };
  } catch (error: any) {
    // Check if it's a 404 error (nothing to delete - this is actually a success case)
    if (error.response?.status === 404) {
      const message = error.response?.data?.message || 'No signing process for root.';
      return {
        success: true,
        hasTask: false,
        message: message,
      };
    }
    
    const errorMessage =
      error.response?.data?.message ||
      error.response?.data?.error ||
      error.message ||
      'Failed to delete signing metadata';
    
    // Check if it's the "no signing process" error (this is also a success case)
    if (
      errorMessage.includes('not in a signing process') ||
      errorMessage.includes('No signing process')
    ) {
      return {
        success: true,
        hasTask: false,
        message: error.response?.data?.message || 'No signing process for root.',
      };
    }
    
    // For other errors, throw
    throw new Error(errorMessage);
  }
};
