# 🎯 Complete Guide: Loaders, Alerts & Timers in React

A comprehensive implementation of professional UI/UX patterns for React applications including loading spinners, toast notifications, countdown timers, and API handling.

## 📦 What's Included

### 1. **Components**

#### `Loader.jsx` - Loading Spinner Component
```jsx
import Loader from './components/Loader';

<Loader 
  isVisible={loading}
  message="Loading data..."
  fullScreen={true}        // true = fixed overlay, false = inline
  size="medium"           // small, medium, large
/>
```

**Features:**
- ✅ Fullscreen and inline modes
- ✅ Customizable size and message
- ✅ Smooth fade-in/out animation
- ✅ Non-blocking UI for inline mode

---

#### `LoaderButton.jsx` - Button with Built-in Loader
```jsx
import LoaderButton from './components/LoaderButton';

<LoaderButton
  isLoading={loading}
  onClick={handleClick}
  className="btn-primary"
  size="medium"
  loadingText="Processing..."
>
  Click Me
</LoaderButton>
```

**Features:**
- ✅ Automatic disable during loading
- ✅ Built-in spinner animation
- ✅ Multiple color variants (primary, secondary, success, danger, warning)
- ✅ Multiple sizes (small, medium, large)
- ✅ Custom loading text

---

### 2. **Custom Hooks**

#### `useApi.js` - API Call Handler
Manages loading state, errors, and success notifications for API calls.

```jsx
import useApi from './hooks/useApi';

const MyComponent = () => {
  const { data, loading, error, execute, reset } = useApi();

  const handleFetchData = async () => {
    await execute(
      async () => {
        return await api.get('/endpoint');
      },
      {
        successMessage: '✅ Data loaded!',
        errorMessage: 'Custom error message',
        onSuccess: (data) => console.log(data),
        onError: (error) => console.error(error),
        showDefaultError: true,
      }
    );
  };

  return (
    <>
      <button onClick={handleFetchData} disabled={loading}>
        {loading ? 'Loading...' : 'Fetch Data'}
      </button>
      {error && <p>Error: {error}</p>}
      {data && <pre>{JSON.stringify(data)}</pre>}
    </>
  );
};
```

**Methods:**
- `execute(apiFunction, options)` - Execute an async function with error handling
- `reset()` - Reset all state (data, loading, error)
- `clearError()` - Clear only the error state

**Options:**
- `successMessage` - Toast shown on success (set to null to disable)
- `errorMessage` - Custom error message
- `onSuccess` - Callback after successful call
- `onError` - Callback after error
- `showDefaultError` - Show error toast (default: true)

---

#### `useTimer.js` - Countdown Timer Hook
Perfect for OTP resend, button cooldowns, etc.

```jsx
import useTimer from './hooks/useTimer';

const OtpComponent = () => {
  const timer = useTimer(30); // 30 seconds

  const handleResendOtp = () => {
    api.post('/resend-otp');
    timer.start();
  };

  return (
    <button 
      onClick={handleResendOtp}
      disabled={timer.isRunning}
    >
      {timer.isRunning ? `Resend in ${timer.timeLeft}s` : 'Resend OTP'}
    </button>
  );
};
```

**Properties:**
- `timeLeft` - Seconds remaining
- `isRunning` - Timer active status
- `isFinished` - Timer completed status
- `hasTimeLeft` - Has time remaining

**Methods:**
- `start()` - Start the countdown
- `stop()` - Stop the countdown
- `reset()` - Reset to initial value
- `getFormattedTime()` - Get formatted time (MM:SS)

---

### 3. **API Utilities**

#### `apiClient.js` - Centralized API Configuration
Pre-configured axios client with interceptors and error handling.

```jsx
import { 
  apiGet, 
  apiPost, 
  apiPut, 
  apiPatch, 
  apiDelete,
  apiUploadFile,
  apiDownloadFile 
} from './utils/apiClient';

// GET request
const data = await apiGet('/users');

// POST request
const user = await apiPost('/users', { name: 'John' });

// PUT request
await apiPut(`/users/${id}`, updatedData);

// PATCH request
await apiPatch(`/users/${id}`, { name: 'Jane' });

// DELETE request
await apiDelete(`/users/${id}`);

// File upload with progress
const formData = new FormData();
formData.append('file', fileInput.files[0]);

await apiUploadFile('/upload', formData, (progress) => {
  console.log(`Upload: ${progress.loaded}/${progress.total}`);
});

// File download
await apiDownloadFile('/download/report', 'report.pdf');
```

**Features:**
- ✅ Auto token injection in headers
- ✅ 401 redirect on expired session
- ✅ Global error handling
- ✅ Timeout configuration
- ✅ File upload with progress tracking
- ✅ File download support

---

### 4. **Toast Notifications**

Using **react-hot-toast** (already configured):

```jsx
import toast from 'react-hot-toast';

// Success
toast.success('Operation successful!');

// Error
toast.error('Something went wrong!');

// Loading
toast.loading('Processing...');

// Custom
toast('Custom message', {
  icon: '👏',
  duration: 4000,
  position: 'top-right',
});
```

---

## 🚀 Complete Example

See `src/pages/ApiDemoPage.jsx` for a full working example with:
- API calls with loaders
- Form validation
- Error handling
- Countdown timers
- Button state management

### How to Use the Demo:
1. Navigate to `/demo` in your app or add the route:
```jsx
import ApiDemoPage from './pages/ApiDemoPage';

<Route path="/demo" element={<ApiDemoPage />} />
```

2. Test all features in the interactive demo page

---

## 📋 Real-World Usage Patterns

### Pattern 1: Simple Data Fetch
```jsx
const DataLoader = () => {
  const { data, loading, error, execute } = useApi();

  useEffect(() => {
    execute(async () => await apiGet('/data'));
  }, []);

  return (
    <>
      <Loader isVisible={loading} />
      {error && <p className="error">{error}</p>}
      {data && <DataTable data={data} />}
    </>
  );
};
```

### Pattern 2: Form Submission
```jsx
const LoginForm = () => {
  const { loading, execute } = useApi();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    await execute(
      () => apiPost('/login', { email, password }),
      {
        successMessage: '✅ Logged in!',
        onSuccess: (data) => {
          localStorage.setItem('token', data.token);
          navigate('/dashboard');
        },
      }
    );
  };

  return (
    <form onSubmit={handleSubmit}>
      <input 
        value={email} 
        onChange={(e) => setEmail(e.target.value)}
        disabled={loading}
      />
      <input 
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        disabled={loading}
      />
      <LoaderButton isLoading={loading} type="submit">
        Login
      </LoaderButton>
    </form>
  );
};
```

### Pattern 3: OTP Resend with Timer
```jsx
const OtpVerification = () => {
  const { loading, execute } = useApi();
  const timer = useTimer(60);

  const handleResend = async () => {
    await execute(
      () => apiPost('/otp/resend'),
      { successMessage: 'OTP sent!' }
    );
    timer.start();
  };

  return (
    <div>
      <OtpInput />
      <LoaderButton
        isLoading={loading}
        onClick={handleResend}
        disabled={timer.isRunning}
      >
        {timer.isRunning ? `Resend in ${timer.timeLeft}s` : 'Resend OTP'}
      </LoaderButton>
    </div>
  );
};
```

### Pattern 4: File Upload with Progress
```jsx
const FileUpload = () => {
  const [progress, setProgress] = useState(0);
  const { loading, execute } = useApi();

  const handleUpload = async (file) => {
    const formData = new FormData();
    formData.append('file', file);

    await execute(
      () => apiUploadFile('/upload', formData, (progressEvent) => {
        const { loaded, total } = progressEvent;
        setProgress(Math.round((loaded / total) * 100));
      }),
      { successMessage: 'File uploaded!' }
    );
  };

  return (
    <>
      <input 
        type="file" 
        onChange={(e) => handleUpload(e.target.files[0])}
        disabled={loading}
      />
      {loading && <p>Upload progress: {progress}%</p>}
    </>
  );
};
```

---

## 🎨 Styling & Customization

### Color Variants for LoaderButton:
- `btn-primary` - Blue gradient
- `btn-secondary` - Gray
- `btn-success` - Green
- `btn-danger` - Red
- `btn-warning` - Orange

### Loader Sizes:
- `small` - 30px
- `medium` - 50px
- `large` - 80px

### Customize Toasts:
```jsx
const Toaster = () => <Toaster position="top-center" />;
```

---

## 📚 Folder Structure

```
src/
├── components/
│   ├── Loader.jsx           # Spinner component
│   ├── Loader.css
│   ├── LoaderButton.jsx     # Button with loader
│   └── LoaderButton.css
├── hooks/
│   ├── useApi.js            # API handler hook
│   └── useTimer.js          # Countdown timer hook
├── utils/
│   └── apiClient.js         # API configuration
├── pages/
│   ├── ApiDemoPage.jsx      # Complete example
│   └── ApiDemoPage.css
└── ...
```

---

## ✅ Best Practices

1. ✅ **Always disable buttons during loading** - Prevents duplicate requests
2. ✅ **Show user feedback** - Use toasts for all important actions
3. ✅ **Handle errors gracefully** - Provide actionable error messages
4. ✅ **Use loaders for context** - Show what operation is happening
5. ✅ **Implement retry logic** - Allow users to retry failed operations
6. ✅ **Reset state on unmount** - Clean up timers and subscriptions
7. ✅ **Validate before API calls** - Reduce server errors
8. ✅ **Use proper HTTP methods** - GET, POST, PUT, PATCH, DELETE

---

## 🐛 Troubleshooting

**Issue: Loader not showing**
- Ensure `isVisible={true}` and `loading` state is correctly updated

**Issue: Toast not appearing**
- Check if `Toaster` component is in your main App component
- Verify `react-hot-toast` is installed

**Issue: Timer not counting down**
- Ensure `start()` is called to begin countdown
- Check if component unmounts during countdown

**Issue: Button stuck in loading state**
- Make sure `error` is caught and loading state is cleared in `.finally()` block

---

## 📞 Support

For issues or questions, refer to:
- React docs: https://react.dev
- react-hot-toast: https://hot-toast.io
- axios: https://axios-http.com

---

**Version:** 1.0.0  
**Last Updated:** 2026-04-01  
**Author:** Your Team
