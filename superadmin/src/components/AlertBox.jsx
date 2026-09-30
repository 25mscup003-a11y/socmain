import React, { useState, useEffect } from 'react';
import './AlertBox.css';

/**
 * Reusable AlertBox Component
 * Inline alert/notification with auto-dismiss option
 */
const AlertBox = ({
  type = 'info', // info, success, error, warning
  title = '',
  message = '',
  isVisible = true,
  onClose = () => {},
  autoDismiss = false,
  dismissTime = 5000,
  closable = true,
  icon = true,
}) => {
  const [show, setShow] = useState(isVisible);

  // Auto dismiss effect
  useEffect(() => {
    if (!show) return;
    
    if (autoDismiss) {
      const timer = setTimeout(() => {
        handleClose();
      }, dismissTime);

      return () => clearTimeout(timer);
    }
  }, [show, autoDismiss, dismissTime]);

  // Update visibility when prop changes
  useEffect(() => {
    setShow(isVisible);
  }, [isVisible]);

  const handleClose = () => {
    setShow(false);
    onClose();
  };

  if (!show) return null;

  // Icon selection
  const icons = {
    info: 'ℹ️',
    success: '✅',
    error: '❌',
    warning: '⚠️',
  };

  const icon_display = icon ? icons[type] : '';

  return (
    <div className={`alert-box alert-${type}`}>
      <div className="alert-content">
        {icon_display && <span className="alert-icon">{icon_display}</span>}
        <div className="alert-text">
          {title && <h4 className="alert-title">{title}</h4>}
          {message && <p className="alert-message">{message}</p>}
        </div>
      </div>
      {closable && (
        <button
          className="alert-close"
          onClick={handleClose}
          aria-label="Close alert"
        >
          ✕
        </button>
      )}
    </div>
  );
};

export default AlertBox;
