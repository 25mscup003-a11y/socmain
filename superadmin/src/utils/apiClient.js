import axios from 'axios';
import toast from 'react-hot-toast';

/**
 * API Utilities for making HTTP requests with built-in error handling
 * Provides centralized API configuration and request/response interceptors
 */

// Create axios instance with base URL
const apiClient = axios.create({
  baseURL: process.env.REACT_APP_API_URL || 'http://localhost:5000/api',
  timeout: 30000, // 30 seconds
  headers: {
    'Content-Type': 'application/json',
  },
});

/**
 * Request Interceptor
 * Add auth token to every request
 */
apiClient.interceptors.request.use(
  (config) => {
    // Add token from localStorage if available
    const token = localStorage.getItem('authToken');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

/**
 * Response Interceptor
 * Handle common error scenarios globally
 */
apiClient.interceptors.response.use(
  (response) => {
    return response.data;
  },
  (error) => {
    // Handle specific error codes
    if (error.response) {
      const { status, data } = error.response;

      // 401: Unauthorized - redirect to login
      if (status === 401) {
        localStorage.removeItem('authToken');
        window.location.href = '/login';
        toast.error('Session expired. Please login again.');
      }

      // 403: Forbidden
      if (status === 403) {
        toast.error(data.message || 'You do not have permission to perform this action');
      }

      // 404: Not Found
      if (status === 404) {
        toast.error(data.message || 'Resource not found');
      }

      // 500: Server Error
      if (status === 500) {
        toast.error('Server error. Please try again later.');
      }

      // Pass the full error response
      return Promise.reject(error);
    }

    // Network error
    if (error.request && !error.response) {
      toast.error('Network error. Please check your internet connection.');
      return Promise.reject(error);
    }

    // Client error
    toast.error(error.message || 'An error occurred');
    return Promise.reject(error);
  }
);

/**
 * GET request
 * @param {String} url - Endpoint URL
 * @param {Object} config - Additional axios config
 * @returns {Promise}
 */
export const apiGet = (url, config = {}) => {
  return apiClient.get(url, config);
};

/**
 * POST request
 * @param {String} url - Endpoint URL
 * @param {Object} data - Request body
 * @param {Object} config - Additional axios config
 * @returns {Promise}
 */
export const apiPost = (url, data = {}, config = {}) => {
  return apiClient.post(url, data, config);
};

/**
 * PUT request
 * @param {String} url - Endpoint URL
 * @param {Object} data - Request body
 * @param {Object} config - Additional axios config
 * @returns {Promise}
 */
export const apiPut = (url, data = {}, config = {}) => {
  return apiClient.put(url, data, config);
};

/**
 * PATCH request
 * @param {String} url - Endpoint URL
 * @param {Object} data - Request body
 * @param {Object} config - Additional axios config
 * @returns {Promise}
 */
export const apiPatch = (url, data = {}, config = {}) => {
  return apiClient.patch(url, data, config);
};

/**
 * DELETE request
 * @param {String} url - Endpoint URL
 * @param {Object} config - Additional axios config
 * @returns {Promise}
 */
export const apiDelete = (url, config = {}) => {
  return apiClient.delete(url, config);
};

/**
 * File upload with multipart/form-data
 * @param {String} url - Endpoint URL
 * @param {Object} formData - FormData object with files
 * @param {Function} onUploadProgress - Progress callback
 * @returns {Promise}
 */
export const apiUploadFile = (url, formData, onUploadProgress = null) => {
  return apiClient.post(url, formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
    onUploadProgress,
  });
};

/**
 * Download file
 * @param {String} url - Endpoint URL
 * @param {String} filename - Name for downloaded file
 * @returns {Promise}
 */
export const apiDownloadFile = async (url, filename = 'download') => {
  try {
    const response = await apiClient.get(url, {
      responseType: 'blob',
    });

    // Create blob and download
    const blob = new Blob([response]);
    const downloadUrl = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(downloadUrl);

    return true;
  } catch (error) {
    console.error('File download error:', error);
    throw error;
  }
};

/**
 * Batch requests
 * @param {Array} requests - Array of request objects
 * @returns {Promise}
 */
export const apiBatch = (requests) => {
  return Promise.all(requests);
};

export default apiClient;
