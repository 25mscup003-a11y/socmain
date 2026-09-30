import React, { useState } from 'react';
import {
  Loader,
  LoaderButton,
  AlertBox,
  FormField,
  Modal,
} from '../components';
import { useApi, useTimer } from '../hooks';
import { apiPost, apiGet } from '../utils';
import toast from 'react-hot-toast';
import './AdvancedFormExample.css';

/**
 * Advanced Form Example
 * Demonstrates complete integration of all components and hooks
 * Features:
 * - Form validation
 * - API calls with loading states
 * - Inline alerts
 * - Countdown timers
 * - Modal loading states
 * - Field-level error handling
 */
const AdvancedFormExample = () => {
  // Form state
  const [formData, setFormData] = useState({
    fullName: '',
    email: '',
    phone: '',
    message: '',
    subscribe: false,
  });

  const [formErrors, setFormErrors] = useState({});

  // API states
  const submitApi = useApi();
  const verifyApi = useApi();

  // Timer for resend verification
  const resendTimer = useTimer(60);

  // Modal states
  const [showVerificationModal, setShowVerificationModal] = useState(false);
  const [verificationCode, setVerificationCode] = useState('');

  // Alert states
  const [showAlert, setShowAlert] = useState(false);
  const [alertData, setAlertData] = useState({
    type: 'info',
    title: '',
    message: '',
  });

  // Validation rules
  const validateForm = () => {
    const errors = {};

    if (!formData.fullName.trim()) {
      errors.fullName = 'Full name is required';
    }

    if (!formData.email.trim()) {
      errors.email = 'Email is required';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      errors.email = 'Please enter a valid email';
    }

    if (!formData.phone.trim()) {
      errors.phone = 'Phone number is required';
    } else if (!/^\d{10}$/.test(formData.phone.replace(/\D/g, ''))) {
      errors.phone = 'Please enter a valid 10-digit phone number';
    }

    if (!formData.message.trim()) {
      errors.message = 'Message is required';
    } else if (formData.message.length < 10) {
      errors.message = 'Message must be at least 10 characters';
    }

    setFormErrors(errors);
    return Object.keys(errors).length === 0;
  };

  // Handle form input change
  const handleInputChange = (e) => {
    const { name, value, type, checked } = e.target;

    setFormData({
      ...formData,
      [name]: type === 'checkbox' ? checked : value,
    });

    // Clear error for this field
    if (formErrors[name]) {
      setFormErrors({
        ...formErrors,
        [name]: '',
      });
    }
  };

  // Show alert helper
  const showAlertMessage = (type, title, message) => {
    setAlertData({ type, title, message });
    setShowAlert(true);
  };

  // Mock API call to submit form
  const mockSubmitForm = async () => {
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve({
          success: true,
          message: 'Form submitted successfully!',
          id: 'SUB-' + Date.now(),
        });
      }, 2000);
    });
  };

  // Mock API call to verify code
  const mockVerifyCode = async (code) => {
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        if (code === '1234') {
          resolve({ status: 'verified' });
        } else {
          reject(new Error('Invalid verification code'));
        }
      }, 1000);
    });
  };

  // Handle form submission
  const handleSubmit = async (e) => {
    e.preventDefault();

    // Validate form
    if (!validateForm()) {
      showAlertMessage(
        'error',
        'Validation Error',
        'Please fix all errors and try again.'
      );
      return;
    }

    // Submit form
    try {
      const result = await submitApi.execute(mockSubmitForm, {
        successMessage: null, // We'll handle this manually
      });

      showAlertMessage(
        'success',
        'Submission Successful!',
        `Your submission ID: ${result.id}`
      );

      // Show verification modal
      setTimeout(() => {
        setShowVerificationModal(true);
        resendTimer.start();
      }, 500);

      // Reset form
      setFormData({
        fullName: '',
        email: '',
        phone: '',
        message: '',
        subscribe: false,
      });
    } catch (err) {
      // Error already shown by useApi
    }
  };

  // Handle verification
  const handleVerify = async () => {
    if (!verificationCode.trim()) {
      toast.error('Please enter verification code');
      return;
    }

    try {
      await verifyApi.execute(
        () => mockVerifyCode(verificationCode),
        {
          successMessage: '✅ Email verified successfully!',
        }
      );

      // Close modal after verification
      setTimeout(() => {
        setShowVerificationModal(false);
        setVerificationCode('');
        resendTimer.reset();
      }, 500);
    } catch (err) {
      // Error already shown
    }
  };

  return (
    <div className="advanced-form-container">
      <div className="advanced-form-wrapper">
        <h1>📋 Advanced Form Example</h1>
        <p className="subtitle">
          Complete example with validation, API calls, alerts, and modals
        </p>

        {/* Alert */}
        {showAlert && (
          <AlertBox
            type={alertData.type}
            title={alertData.title}
            message={alertData.message}
            isVisible={showAlert}
            onClose={() => setShowAlert(false)}
            closable={true}
          />
        )}

        {/* Fullscreen Loader while submitting */}
        <Loader
          isVisible={submitApi.loading}
          message="Submitting your form..."
          fullScreen={false}
          size="large"
        />

        {/* Main Form */}
        <form onSubmit={handleSubmit} className="advanced-form">
          <div className="form-section">
            <h2>📝 Contact Information</h2>

            <FormField
              label="Full Name"
              name="fullName"
              type="text"
              value={formData.fullName}
              onChange={handleInputChange}
              placeholder="John Doe"
              error={formErrors.fullName}
              required={true}
              disabled={submitApi.loading}
              helperText="Please enter your full name"
            />

            <FormField
              label="Email Address"
              name="email"
              type="email"
              value={formData.email}
              onChange={handleInputChange}
              placeholder="john@example.com"
              error={formErrors.email}
              required={true}
              disabled={submitApi.loading}
              helperText="We'll send verification code to this email"
            />

            <FormField
              label="Phone Number"
              name="phone"
              type="text"
              value={formData.phone}
              onChange={handleInputChange}
              placeholder="(555) 123-4567"
              error={formErrors.phone}
              required={true}
              disabled={submitApi.loading}
              helperText="10-digit phone number"
            />
          </div>

          <div className="form-section">
            <h2>💬 Your Message</h2>

            <FormField
              label="Message"
              name="message"
              type="textarea"
              value={formData.message}
              onChange={handleInputChange}
              placeholder="Tell us what you think..."
              error={formErrors.message}
              required={true}
              disabled={submitApi.loading}
              maxLength={500}
              rows={5}
              helperText="Minimum 10 characters"
            />
          </div>

          <div className="form-section">
            <FormField
              label="Subscribe to our newsletter"
              name="subscribe"
              type="checkbox"
              checked={formData.subscribe}
              onChange={handleInputChange}
              disabled={submitApi.loading}
              helperText="Receive updates and special offers"
            />
          </div>

          <div className="form-actions">
            <LoaderButton
              type="submit"
              isLoading={submitApi.loading}
              className="btn-primary"
              size="medium"
              loadingText="Submitting..."
            >
              ✉️ Submit Form
            </LoaderButton>

            <button
              type="reset"
              className="btn btn-secondary"
              disabled={submitApi.loading}
              onClick={() => {
                setFormData({
                  fullName: '',
                  email: '',
                  phone: '',
                  message: '',
                  subscribe: false,
                });
                setFormErrors({});
              }}
            >
              🔄 Reset Form
            </button>
          </div>
        </form>

        {/* Verification Modal */}
        <Modal
          isOpen={showVerificationModal}
          title="📧 Verify Your Email"
          closeOnBackdrop={false}
          closeButton={!verifyApi.loading}
          isLoading={verifyApi.loading}
          onClose={() => setShowVerificationModal(false)}
          size="small"
          footer={
            <div style={{ display: 'flex', gap: '1rem', width: '100%' }}>
              <button
                className="btn btn-secondary"
                onClick={() => setShowVerificationModal(false)}
                disabled={verifyApi.loading}
                style={{ flex: 1 }}
              >
                Cancel
              </button>
              <button
                className="btn btn-primary"
                onClick={handleVerify}
                disabled={verifyApi.loading || !verificationCode.trim()}
                style={{ flex: 1 }}
              >
                {verifyApi.loading ? 'Verifying...' : 'Verify'}
              </button>
            </div>
          }
        >
          <div className="modal-content">
            <p>
              We've sent a verification code to <strong>{formData.email}</strong>
            </p>

            <FormField
              label="Verification Code"
              name="verificationCode"
              type="text"
              value={verificationCode}
              onChange={(e) => setVerificationCode(e.target.value)}
              placeholder="Enter 4-digit code"
              disabled={verifyApi.loading}
              helperText="Check your email for the code"
            />

            <div className="resend-section">
              <button
                type="button"
                className="btn btn-link"
                onClick={() => {
                  toast.success('✅ Code resent to your email');
                  resendTimer.start();
                }}
                disabled={resendTimer.isRunning || verifyApi.loading}
              >
                {resendTimer.isRunning
                  ? `Resend code in ${resendTimer.timeLeft}s`
                  : 'Resend Code'}
              </button>
            </div>
          </div>
        </Modal>

        {/* Demo Instructions */}
        <div className="demo-instructions">
          <h3>💡 Demo Instructions:</h3>
          <ul>
            <li>Fill in all fields to enable the submit button</li>
            <li>Submit the form to see the verification modal</li>
            <li>
              Enter <strong>1234</strong> as the verification code
            </li>
            <li>Try entering invalid data to see error handling</li>
            <li>Watch the timer countdown for resending the code</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default AdvancedFormExample;
