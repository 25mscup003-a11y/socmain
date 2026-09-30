import React from 'react';
import './Loader.css';

/**
 * Reusable Loader (Spinner) Component
 * Shows a loading spinner with optional message
 * Can be used as overlay or inline
 */
const Loader = ({ 
  isVisible = false, 
  message = 'Loading...', 
  fullScreen = false,
  size = 'medium' // small, medium, large
}) => {
  if (!isVisible) return null;

  return (
    <div className={`loader-container ${fullScreen ? 'loader-fullscreen' : 'loader-inline'}`}>
      <div className={`loader-spinner loader-${size}`}></div>
      {message && <p className="loader-message">{message}</p>}
    </div>
  );
};

export default Loader;
