import React from 'react';
import './LoaderButton.css';

/**
 * Reusable LoaderButton Component
 * Button with built-in loader state management
 * Automatically disables and shows loading state
 */
const LoaderButton = ({
  isLoading = false,
  onClick = () => {},
  children,
  className = 'btn-primary',
  disabled = false,
  size = 'medium', // small, medium, large
  type = 'button',
  loadingText = 'Loading...',
  ...props
}) => {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={isLoading || disabled}
      className={`loader-button loader-button-${size} ${className} ${isLoading ? 'loading' : ''}`}
      {...props}
    >
      {isLoading ? (
        <>
          <span className="loader-button-spinner"></span>
          <span className="loader-button-text">{loadingText}</span>
        </>
      ) : (
        children
      )}
    </button>
  );
};

export default LoaderButton;
