/**
 * Form Utilities and Helpers
 * Common patterns and validation functions for forms
 */

/**
 * Validation Rules
 */
export const validationRules = {
  /**
   * Email validation
   */
  email: (value) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!value) return 'Email is required';
    if (!emailRegex.test(value)) return 'Invalid email format';
    return null;
  },

  /**
   * Password validation (minimum 8 chars, 1 uppercase, 1 number)
   */
  password: (value) => {
    if (!value) return 'Password is required';
    if (value.length < 8) return 'Password must be at least 8 characters';
    if (!/[A-Z]/.test(value)) return 'Password must contain an uppercase letter';
    if (!/[0-9]/.test(value)) return 'Password must contain a number';
    return null;
  },

  /**
   * Phone number validation (10 digits)
   */
  phone: (value) => {
    if (!value) return 'Phone number is required';
    const phoneRegex = /^\d{10}$/;
    if (!phoneRegex.test(value.replace(/\D/g, ''))) {
      return 'Phone number must be 10 digits';
    }
    return null;
  },

  /**
   * Required field validation
   */
  required: (value, fieldName = 'Field') => {
    if (!value || value.trim() === '') return `${fieldName} is required`;
    return null;
  },

  /**
   * Minimum length validation
   */
  minLength: (value, minLength, fieldName = 'Field') => {
    if (!value) return null;
    if (value.length < minLength) {
      return `${fieldName} must be at least ${minLength} characters`;
    }
    return null;
  },

  /**
   * Maximum length validation
   */
  maxLength: (value, maxLength, fieldName = 'Field') => {
    if (!value) return null;
    if (value.length > maxLength) {
      return `${fieldName} must not exceed ${maxLength} characters`;
    }
    return null;
  },

  /**
   * URL validation
   */
  url: (value) => {
    if (!value) return 'URL is required';
    try {
      new URL(value);
      return null;
    } catch {
      return 'Invalid URL';
    }
  },

  /**
   * Number validation
   */
  number: (value) => {
    if (!value) return 'Number is required';
    if (isNaN(value)) return 'Must be a valid number';
    return null;
  },

  /**
   * Credit card validation
   */
  creditCard: (value) => {
    if (!value) return 'Card number is required';
    const cardRegex = /^\d{13,19}$/;
    if (!cardRegex.test(value.replace(/\s/g, ''))) {
      return 'Invalid card number';
    }
    return null;
  },

  /**
   * Zip code validation
   */
  zipCode: (value) => {
    if (!value) return 'Zip code is required';
    const zipRegex = /^\d{5}(-\d{4})?$/;
    if (!zipRegex.test(value)) return 'Invalid zip code format';
    return null;
  },
};

/**
 * Validate form data against rules
 * @param {Object} data - Form data to validate
 * @param {Object} rules - Validation rules {fieldName: validationFn}
 * @returns {Object} Errors object
 */
export const validateFormData = (data, rules) => {
  const errors = {};

  Object.keys(rules).forEach((fieldName) => {
    const rule = rules[fieldName];
    const value = data[fieldName];

    if (typeof rule === 'function') {
      const error = rule(value);
      if (error) {
        errors[fieldName] = error;
      }
    } else if (Array.isArray(rule)) {
      // Multiple validation rules for one field
      for (const singleRule of rule) {
        const error = singleRule(value);
        if (error) {
          errors[fieldName] = error;
          break;
        }
      }
    }
  });

  return errors;
};

/**
 * Form handler hook pattern helper
 * Simplifies state management for forms
 */
export const useFormHandler = (initialValues, onSubmit) => {
  const [values, setValues] = React.useState(initialValues);
  const [errors, setErrors] = React.useState({});
  const [touched, setTouched] = React.useState({});
  const [isSubmitting, setIsSubmitting] = React.useState(false);

  const handleChange = React.useCallback((e) => {
    const { name, value, type, checked } = e.target;
    setValues((prev) => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value,
    }));
  }, []);

  const handleBlur = React.useCallback((e) => {
    const { name } = e.target;
    setTouched((prev) => ({ ...prev, [name]: true }));
  }, []);

  const handleSubmit = React.useCallback(
    async (e, validationRules = {}) => {
      e.preventDefault();
      setIsSubmitting(true);

      // Validate form
      const formErrors = validateFormData(values, validationRules);

      if (Object.keys(formErrors).length > 0) {
        setErrors(formErrors);
        setIsSubmitting(false);
        return;
      }

      // Call submit handler
      try {
        await onSubmit(values);
        setValues(initialValues);
        setErrors({});
        setTouched({});
      } catch (error) {
        console.error('Form submission error:', error);
      } finally {
        setIsSubmitting(false);
      }
    },
    [values, initialValues, onSubmit]
  );

  const resetForm = React.useCallback(() => {
    setValues(initialValues);
    setErrors({});
    setTouched({});
  }, [initialValues]);

  return {
    values,
    errors,
    touched,
    isSubmitting,
    handleChange,
    handleBlur,
    handleSubmit,
    resetForm,
    setFieldValue: (name, value) =>
      setValues((prev) => ({ ...prev, [name]: value })),
    setFieldError: (name, error) =>
      setErrors((prev) => ({ ...prev, [name]: error })),
  };
};

/**
 * Format phone number (123-456-7890)
 */
export const formatPhoneNumber = (value) => {
  const digits = value.replace(/\D/g, '');
  if (digits.length <= 3) return digits;
  if (digits.length <= 6) return `${digits.slice(0, 3)}-${digits.slice(3)}`;
  return `${digits.slice(0, 3)}-${digits.slice(3, 6)}-${digits.slice(6, 10)}`;
};

/**
 * Format currency (USD by default)
 */
export const formatCurrency = (value, currency = 'USD') => {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency,
  }).format(value);
};

/**
 * Format date
 */
export const formatDate = (date, format = 'MM/DD/YYYY') => {
  const d = new Date(date);
  const day = String(d.getDate()).padStart(2, '0');
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const year = d.getFullYear();

  return format
    .replace('DD', day)
    .replace('MM', month)
    .replace('YYYY', year);
};

/**
 * Get field error message (only if touched)
 */
export const getFieldError = (fieldName, errors, touched) => {
  return touched[fieldName] ? errors[fieldName] : null;
};

/**
 * Check if form has errors
 */
export const hasFormErrors = (errors) => {
  return Object.keys(errors).length > 0;
};

/**
 * Serialize form data to FormData object
 */
export const serializeFormData = (data) => {
  const formData = new FormData();

  Object.keys(data).forEach((key) => {
    const value = data[key];

    if (value instanceof File) {
      formData.append(key, value);
    } else if (Array.isArray(value)) {
      value.forEach((item, index) => {
        if (item instanceof File) {
          formData.append(`${key}[${index}]`, item);
        } else {
          formData.append(`${key}[]`, item);
        }
      });
    } else if (value !== null && value !== undefined) {
      formData.append(key, value);
    }
  });

  return formData;
};

/**
 * Debounce form submission to prevent duplicate requests
 */
export const debounceSubmit = (fn, delay = 300) => {
  let timeoutId = null;

  return (...args) => {
    if (timeoutId) clearTimeout(timeoutId);
    timeoutId = setTimeout(() => fn(...args), delay);
  };
};

export default {
  validationRules,
  validateFormData,
  formatPhoneNumber,
  formatCurrency,
  formatDate,
  getFieldError,
  hasFormErrors,
  serializeFormData,
  debounceSubmit,
};
