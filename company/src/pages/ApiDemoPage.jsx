import React, { useState } from 'react';
import Loader from '../components/Loader';
import useApi from '../hooks/useApi';
import useTimer from '../hooks/useTimer';
import toast from 'react-hot-toast';
import './ApiDemoPage.css';

/**
 * Demo Page: Shows complete usage of Loader, useApi, useTimer, and Alerts
 * This page demonstrates all features:
 * 1. API calls with loading state
 * 2. Error and success handling
 * 3. Countdown timer for resend actions
 * 4. Disabled buttons during operations
 */
const ApiDemoPage = () => {
  // API hooks
  const fetchDataApi = useApi();
  const loginApi = useApi();
  const resendOtpApi = useApi();

  // Timer for OTP resend
  const resendTimer = useTimer(30);

  // State for form
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  // Mock API functions
  const mockFetchData = async () => {
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        // Simulate 70% success rate
        if (Math.random() > 0.3) {
          resolve({
            id: 1,
            name: 'John Doe',
            email: 'john@example.com',
            role: 'Admin',
          });
        } else {
          reject(new Error('Failed to fetch data. Please try again.'));
        }
      }, 2000);
    });
  };

  const mockLogin = async () => {
    if (!email || !password) {
      throw new Error('Please fill in all fields');
    }

    return new Promise((resolve, reject) => {
      setTimeout(() => {
        if (email && password.length > 3) {
          resolve({
            token: 'auth_token_12345',
            user: { email, name: 'User' },
          });
        } else {
          reject(new Error('Invalid email or password'));
        }
      }, 1500);
    });
  };

  const mockResendOtp = async () => {
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve({ message: 'OTP sent successfully' });
      }, 1000);
    });
  };

  // Handle fetch data
  const handleFetchData = async () => {
    try {
      await fetchDataApi.execute(mockFetchData, {
        successMessage: '✅ Data fetched successfully!',
      });
    } catch (err) {
      // Error is already handled in useApi
    }
  };

  // Handle login
  const handleLogin = async () => {
    try {
      await loginApi.execute(mockLogin, {
        successMessage: '✅ Login successful!',
        onSuccess: (data) => {
          console.log('User logged in:', data);
          // You can redirect or update global state here
        },
      });
    } catch (err) {
      // Error is already handled
    }
  };

  // Handle resend OTP
  const handleResendOtp = async () => {
    try {
      await resendOtpApi.execute(mockResendOtp, {
        successMessage: '✅ OTP resent! Check your email.',
      });
      // Start the countdown timer
      resendTimer.start();
    } catch (err) {
      // Error is already handled
    }
  };

  return (
    <div className="demo-container">
      {/* Fullscreen Loader */}
      <Loader
        isVisible={fetchDataApi.loading}
        message="Fetching data..."
        fullScreen={false}
        size="medium"
      />

      <div className="demo-content">
        <h1>🎯 API Loader & Alert Demo</h1>
        <p className="subtitle">
          Complete example of handling API calls, loading states, and notifications
        </p>

        {/* Section 1: Fetch Data with Loading */}
        <section className="demo-section">
          <h2>📊 Section 1: Fetch Data with Loader</h2>
          <p>
            Shows a loader while fetching data. Success/error messages are
            displayed using react-hot-toast.
          </p>

          <div className="demo-box">
            <button
              className="btn btn-primary"
              onClick={handleFetchData}
              disabled={fetchDataApi.loading}
            >
              {fetchDataApi.loading ? 'Loading...' : 'Fetch Data'}
            </button>

            {fetchDataApi.data && (
              <div className="success-box">
                <h3>✅ Fetched Data:</h3>
                <pre>{JSON.stringify(fetchDataApi.data, null, 2)}</pre>
              </div>
            )}

            {fetchDataApi.error && (
              <div className="error-box">
                <p>❌ Error: {fetchDataApi.error}</p>
                <button className="btn btn-small" onClick={fetchDataApi.clearError}>
                  Dismiss
                </button>
              </div>
            )}
          </div>
        </section>

        {/* Section 2: Login Form */}
        <section className="demo-section">
          <h2>🔐 Section 2: Login Form with Validation</h2>
          <p>
            Form validation + disabled buttons during API calls + toast
            notifications
          </p>

          <div className="demo-box">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleLogin();
              }}
            >
              <div className="form-group">
                <label>Email:</label>
                <input
                  type="email"
                  placeholder="your@email.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  disabled={loginApi.loading}
                />
              </div>

              <div className="form-group">
                <label>Password:</label>
                <input
                  type="password"
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={loginApi.loading}
                />
              </div>

              <button
                type="submit"
                className="btn btn-primary"
                disabled={loginApi.loading}
              >
                {loginApi.loading ? 'Logging in...' : 'Login'}
              </button>
            </form>

            {loginApi.data && (
              <div className="success-box">
                <h3>✅ Login Successful!</h3>
                <p>Token: {loginApi.data.token}</p>
              </div>
            )}
          </div>
        </section>

        {/* Section 3: Resend OTP with Countdown */}
        <section className="demo-section">
          <h2>⏱️ Section 3: Resend OTP with Countdown Timer</h2>
          <p>
            Timer disables the button and shows countdown. User must wait before
            resending.
          </p>

          <div className="demo-box">
            <button
              className="btn btn-primary"
              onClick={handleResendOtp}
              disabled={resendTimer.isRunning || resendOtpApi.loading}
            >
              {resendOtpApi.loading ? (
                'Sending OTP...'
              ) : resendTimer.isRunning ? (
                `Resend OTP in ${resendTimer.timeLeft}s`
              ) : (
                'Resend OTP'
              )}
            </button>

            <div className="timer-info">
              {resendTimer.isRunning && (
                <p>⏳ Timer active: {resendTimer.getFormattedTime()}</p>
              )}
              {resendTimer.isFinished && !resendTimer.isRunning && (
                <p>✅ You can resend OTP now</p>
              )}
            </div>
          </div>
        </section>

        {/* Section 4: Component Reference */}
        <section className="demo-section reference">
          <h2>📚 Reference: How to Use</h2>

          <div className="code-block">
            <h3>1️⃣ useApi Hook</h3>
            <pre>{`
const { data, loading, error, execute } = useApi();

await execute(async () => {
  return await apiCall();
}, {
  successMessage: 'Success!',
  errorMessage: 'Custom error',
  onSuccess: (data) => console.log(data),
});
            `}</pre>
          </div>

          <div className="code-block">
            <h3>2️⃣ useTimer Hook</h3>
            <pre>{`
const { timeLeft, isRunning, start, reset } = useTimer(30);

<button disabled={isRunning}>
  Resend {isRunning && \`in \${timeLeft}s\`}
</button>

start(); // Start countdown
            `}</pre>
          </div>

          <div className="code-block">
            <h3>3️⃣ Loader Component</h3>
            <pre>{`
<Loader 
  isVisible={loading} 
  message="Loading..." 
  fullScreen={false}
  size="medium"
/>
            `}</pre>
          </div>

          <div className="code-block">
            <h3>4️⃣ Toast Notifications</h3>
            <pre>{`
import toast from 'react-hot-toast';

toast.success('Success message');
toast.error('Error message');
toast.loading('Loading message');
            `}</pre>
          </div>
        </section>

        {/* Reset All Button */}
        <section className="demo-section">
          <button
            className="btn btn-secondary"
            onClick={() => {
              fetchDataApi.reset();
              loginApi.reset();
              resendOtpApi.reset();
              resendTimer.reset();
              setEmail('');
              setPassword('');
              toast('All states reset!');
            }}
          >
            🔄 Reset All
          </button>
        </section>
      </div>
    </div>
  );
};

export default ApiDemoPage;
