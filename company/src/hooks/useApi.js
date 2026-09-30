import { useState, useCallback } from 'react';
import toast from 'react-hot-toast';

/**
 * Custom Hook for API Handling
 * Manages loading state, error handling, and success notifications
 * 
 * Usage:
 * const { data, loading, error, execute, reset } = useApi();
 * 
 * await execute(async () => {
 *   return await apiCall();
 * });
 */
const useApi = () => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  /**
   * Execute an API call with error handling
   * @param {Function} apiFunction - Async function to execute
   * @param {Object} options - Configuration options
   * @param {String} options.successMessage - Message to show on success (if null, no toast shown)
   * @param {String} options.errorMessage - Custom error message
   * @param {Function} options.onSuccess - Callback after successful API call
   * @param {Function} options.onError - Callback after error
   * @param {Boolean} options.showDefaultError - Show default error toast (default: true)
   */
  const execute = useCallback(
    async (apiFunction, options = {}) => {
      const {
        successMessage = 'Operation successful!',
        errorMessage = null,
        onSuccess = null,
        onError = null,
        showDefaultError = true,
      } = options;

      try {
        setLoading(true);
        setError(null);

        // Execute the API function
        const result = await apiFunction();
        setData(result);

        // Show success toast if successMessage is provided
        if (successMessage) {
          toast.success(successMessage);
        }

        // Call onSuccess callback if provided
        if (onSuccess) {
          onSuccess(result);
        }

        return result;
      } catch (err) {
        console.error('API Error:', err);

        // Set error state
        const errorMsg =
          errorMessage ||
          err.response?.data?.message ||
          err.message ||
          'An error occurred. Please try again.';

        setError(errorMsg);

        // Show error toast if enabled
        if (showDefaultError) {
          toast.error(errorMsg);
        }

        // Call onError callback if provided
        if (onError) {
          onError(err);
        }

        throw err;
      } finally {
        setLoading(false);
      }
    },
    []
  );

  /**
   * Reset the hook state
   */
  const reset = useCallback(() => {
    setData(null);
    setLoading(false);
    setError(null);
  }, []);

  /**
   * Clear only the error
   */
  const clearError = useCallback(() => {
    setError(null);
  }, []);

  return {
    data,
    loading,
    error,
    execute,
    reset,
    clearError,
    setData, // Allow manual data updates
  };
};

export default useApi;
