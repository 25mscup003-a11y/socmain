import React from 'react';
import './FormField.css';

/**
 * Reusable FormField Component
 * Combines input/textarea with error display and loading state
 */
const FormField = ({
  type = 'text', // text, email, password, textarea, select, checkbox
  label = '',
  name = '',
  value = '',
  onChange = () => {},
  onBlur = () => {},
  placeholder = '',
  error = null,
  required = false,
  disabled = false,
  isLoading = false,
  className = '',
  options = [], // For select type
  maxLength = null,
  rows = 4, // For textarea
  helperText = '',
  ...props
}) => {
  const renderInput = () => {
    const baseProps = {
      type: type,
      name: name,
      value: value,
      onChange: onChange,
      onBlur: onBlur,
      placeholder: placeholder,
      disabled: disabled || isLoading,
      className: `form-field-input ${error ? 'error' : ''} ${isLoading ? 'loading' : ''}`,
      ...props,
    };

    if (type === 'textarea') {
      return (
        <textarea
          {...baseProps}
          rows={rows}
          maxLength={maxLength}
        />
      );
    }

    if (type === 'select') {
      return (
        <select {...baseProps}>
          <option value="" disabled>
            Select {label}
          </option>
          {options.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
      );
    }

    if (type === 'checkbox') {
      return (
        <input
          type="checkbox"
          {...baseProps}
          className={`form-field-checkbox ${error ? 'error' : ''}`}
        />
      );
    }

    return <input {...baseProps} />;
  };

  return (
    <div className={`form-field ${className}`}>
      {label && (
        <label className="form-field-label">
          {label}
          {required && <span className="required">*</span>}
        </label>
      )}

      <div className="form-field-wrapper">
        {renderInput()}
        {isLoading && <span className="form-field-loader">⏳</span>}
      </div>

      {error && <p className="form-field-error">{error}</p>}
      {helperText && !error && <p className="form-field-helper">{helperText}</p>}

      {type === 'textarea' && maxLength && (
        <small className="form-field-count">
          {value.length} / {maxLength}
        </small>
      )}
    </div>
  );
};

export default FormField;
