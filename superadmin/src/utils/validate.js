// Frontend validation helpers — mirrors backend validate.js
// Returns error string or null

export const validateEmail = (v) => {
  if (!v?.trim()) return 'Email is required';
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v.trim())) return 'Invalid email address';
  return null;
};

export const validatePassword = (v) => {
  if (!v) return 'Password is required';
  if (v.length < 8) return 'Password must be at least 8 characters';
  return null;
};

export const validatePhone = (v) => {
  if (!v) return null; // optional
  if (!/^[\d\s\+\-\(\)]{7,15}$/.test(v)) return 'Invalid phone number (7-15 digits)';
  return null;
};

export const validateCompanyName = (v) => {
  if (!v?.trim()) return 'Company name is required';
  if (v.trim().length < 2)  return 'Company name must be at least 2 characters';
  if (v.trim().length > 100) return 'Company name too long (max 100 characters)';
  return null;
};

export const validateDeptName = (v) => {
  if (!v?.trim()) return 'Department name is required';
  if (v.trim().length < 1)  return 'Department name is required';
  if (v.trim().length > 80) return 'Department name too long (max 80 characters)';
  return null;
};

export const validateSystemName = (v) => {
  if (!v?.trim()) return 'System name is required';
  if (v.trim().length < 1)  return 'System name is required';
  if (v.trim().length > 80) return 'System name too long (max 80 characters)';
  return null;
};

export const validateName = (v, label = 'Name') => {
  if (!v?.trim()) return `${label} is required`;
  if (v.trim().length < 2) return `${label} must be at least 2 characters`;
  return null;
};

// Run array of validators and return first error string or null
export const firstError = (...validators) => {
  for (const err of validators) {
    if (err) return err;
  }
  return null;
};
