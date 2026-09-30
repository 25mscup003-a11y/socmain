import React from 'react';
import './Modal.css';

/**
 * Reusable Modal Component
 * Flexible modal for confirmations, forms, loading states, etc.
 */
const Modal = ({
  isOpen = false,
  title = '',
  children = null,
  footer = null,
  onClose = () => {},
  closeOnBackdrop = true,
  closeButton = true,
  size = 'medium', // small, medium, large
  isLoading = false,
}) => {
  if (!isOpen) return null;

  const handleBackdropClick = (e) => {
    if (closeOnBackdrop && e.target === e.currentTarget) {
      onClose();
    }
  };

  return (
    <div className="modal-backdrop" onClick={handleBackdropClick}>
      <div className={`modal modal-${size}`}>
        {/* Modal Header */}
        {title && (
          <div className="modal-header">
            <h2 className="modal-title">{title}</h2>
            {closeButton && (
              <button
                className="modal-close-button"
                onClick={onClose}
                aria-label="Close modal"
                disabled={isLoading}
              >
                ✕
              </button>
            )}
          </div>
        )}

        {/* Modal Body */}
        <div className={`modal-body ${isLoading ? 'loading' : ''}`}>
          {isLoading ? (
            <div className="modal-loading">
              <div className="modal-spinner"></div>
              <p>Loading...</p>
            </div>
          ) : (
            children
          )}
        </div>

        {/* Modal Footer */}
        {footer && (
          <div className="modal-footer">
            {footer}
          </div>
        )}
      </div>
    </div>
  );
};

export default Modal;
