# ⚡ Quick Reference Card

## 🚀 Quick Start Snippets

### 1. Simple API Call with Loader
```jsx
import { Loader } from './components';
import { useApi } from './hooks';
import { apiGet } from './utils';

const MyComponent = () => {
  const { data, loading, execute } = useApi();

  const handleFetch = () => {
    execute(() => apiGet('/data'));
  };

  return (
    <>
      <Loader isVisible={loading} />
      <button onClick={handleFetch}>Fetch</button>
      {data && <div>{JSON.stringify(data)}</div>}
    </>
  );
};
```

### 2. Form with Validation
```jsx
import { FormField, LoaderButton, AlertBox } from './components';
import { useApi } from './hooks';
import { apiPost, validateFormData, validationRules } from './utils';

const LoginForm = () => {
  const [formData, setFormData] = useState({ email: '', password: '' });
  const [errors, setErrors] = useState({});
  const { loading, error, execute } = useApi();

  const handleSubmit = async (e) => {
    e.preventDefault();
    const newErrors = validateFormData(formData, {
      email: validationRules.email,
      password: validationRules.password,
    });
    
    if (Object.keys(newErrors).length) {
      setErrors(newErrors);
      return;
    }

    await execute(() => apiPost('/login', formData));
  };

  return (
    <form onSubmit={handleSubmit}>
      {error && <AlertBox type="error" message={error} />}
      <FormField
        label="Email"
        name="email"
        type="email"
        value={formData.email}
        onChange={(e) => setFormData({...formData, email: e.target.value})}
        error={errors.email}
      />
      <FormField
        label="Password"
        name="password"
        type="password"
        value={formData.password}
        onChange={(e) => setFormData({...formData, password: e.target.value})}
        error={errors.password}
      />
      <LoaderButton type="submit" isLoading={loading}>
        Login
      </LoaderButton>
    </form>
  );
};
```

### 3. OTP Countdown Timer
```jsx
import { LoaderButton } from './components';
import { useTimer } from './hooks';

const ResendOTP = () => {
  const timer = useTimer(60);

  const handleResend = () => {
    // API call here
    timer.start();
  };

  return (
    <LoaderButton
      onClick={handleResend}
      disabled={timer.isRunning}
    >
      {timer.isRunning ? `Resend in ${timer.timeLeft}s` : 'Resend OTP'}
    </LoaderButton>
  );
};
```

### 4. Modal with Loading
```jsx
import { Modal, FormField, LoaderButton } from './components';
import { useApi } from './hooks';

const VerificationModal = ({ isOpen, onClose, email }) => {
  const [code, setCode] = useState('');
  const { loading, execute } = useApi();

  const handleVerify = async () => {
    await execute(() => apiPost('/verify', { email, code }));
  };

  return (
    <Modal isOpen={isOpen} title="Verify Email" onClose={onClose}>
      <FormField
        label="Verification Code"
        value={code}
        onChange={(e) => setCode(e.target.value)}
        placeholder="Enter 4-digit code"
      />
      <LoaderButton isLoading={loading} onClick={handleVerify}>
        Verify
      </LoaderButton>
    </Modal>
  );
};
```

---

## 📚 Component Props Cheat Sheet

| Component | Key Props | Default |
|-----------|-----------|---------|
| `Loader` | `isVisible`, `message`, `fullScreen`, `size` | false, "Loading...", false, "medium" |
| `LoaderButton` | `isLoading`, `onClick`, `className`, `size`, `loadingText` | false, ()=>{}, "btn-primary", "medium", "Loading..." |
| `AlertBox` | `type`, `title`, `message`, `autoDismiss`, `dismissTime` | "info", "", "", false, 5000 |
| `FormField` | `label`, `name`, `type`, `value`, `error`, `required` | "", "", "text", "", null, false |
| `Modal` | `isOpen`, `title`, `onClose`, `size`, `isLoading` | false, "", ()=>{}, "medium", false |

---

## 🔌 API Methods

```jsx
// GET
const data = await apiGet('/endpoint');

// POST
const result = await apiPost('/endpoint', { data });

// PUT
await apiPut('/endpoint/id', { data });

// PATCH
await apiPatch('/endpoint/id', { data });

// DELETE
await apiDelete('/endpoint/id');

// File Upload
await apiUploadFile('/upload', formData, onProgress);

// Download
await apiDownloadFile('/download', 'filename.pdf');
```

---

## ✔️ Validation Rules Quick List

```jsx
import { validationRules } from './utils';

validationRules.email(value);          // Email validation
validationRules.password(value);       // 8+ chars, 1 uppercase, 1 number
validationRules.phone(value);          // 10 digits
validationRules.required(value, name); // Required field
validationRules.minLength(v, 8, name); // Min length
validationRules.maxLength(v, 50, name); // Max length
validationRules.url(value);            // URL validation
validationRules.number(value);         // Number validation
validationRules.creditCard(value);     // Credit card
validationRules.zipCode(value);        // Zip code
```

---

## 🎯 useApi Hook Quick Reference

```jsx
const { data, loading, error, execute, reset, clearError } = useApi();

// Basic usage
await execute(apiFunction);

// With options
await execute(apiFunction, {
  successMessage: 'Success!',
  errorMessage: 'Custom error',
  onSuccess: (data) => console.log(data),
  onError: (err) => console.error(err),
});
```

---

## ⏱️ useTimer Hook Quick Reference

```jsx
const { timeLeft, isRunning, isFinished, start, stop, reset, getFormattedTime } = useTimer(60);

timer.start();                    // Start countdown
timer.stop();                     // Pause countdown
timer.reset();                    // Reset to initial
timer.getFormattedTime();         // Returns "00:30"
timer.timeLeft;                   // Seconds remaining
timer.isRunning;                  // Is active
```

---

## 🎨 Styling Quick Tips

### Change Primary Color
```css
/* In any component's CSS */
--primary: #667eea;  /* Change this */
```

### Button Variants
```jsx
<LoaderButton className="btn-primary">Primary</LoaderButton>
<LoaderButton className="btn-secondary">Secondary</LoaderButton>
<LoaderButton className="btn-success">Success</LoaderButton>
<LoaderButton className="btn-danger">Danger</LoaderButton>
<LoaderButton className="btn-warning">Warning</LoaderButton>
```

### Loader Sizes
```jsx
<Loader size="small" />    {/* 30px */}
<Loader size="medium" />   {/* 50px */}
<Loader size="large" />    {/* 80px */}
```

### Alert Types
```jsx
<AlertBox type="info" />    {/* Blue */}
<AlertBox type="success" /> {/* Green */}
<AlertBox type="error" />   {/* Red */}
<AlertBox type="warning" /> {/* Orange */}
```

---

## 🐛 Debug Tips

### Check if loading state is stuck
```jsx
console.log('Loading:', loading);
console.log('Error:', error);
```

### Verify API response
```jsx
await execute(async () => {
  const resp = await apiGet('/endpoint');
  console.log('Response:', resp);
  return resp;
});
```

### Test timer
```jsx
console.log('Timer:', { timeLeft: timer.timeLeft, isRunning: timer.isRunning });
```

---

## 📱 Responsive Breakpoints

- Mobile: < 768px
- Tablet: 768px - 1024px
- Desktop: > 1024px

Components auto-adjust at these breakpoints.

---

## 🚨 Common Error Messages

| Error | Cause | Fix |
|-------|-------|-----|
| Loader not showing | `isVisible` is false | Check loading state |
| Toast not appearing | No `<Toaster />` in App | Add to App.jsx |
| Form not submitting | Validation errors | Check console for errors |
| Timer frozen | Unmounted during countdown | Use cleanup in useEffect |
| API 401 | Token expired | Check localStorage auth |
| API 403 | No permission | Check user role |

---

## ⌨️ Keyboard Shortcuts Test

- Tab: Navigate between fields
- Enter: Submit form
- Escape: Close modal / clear input

---

## 📞 Support Resources

- **React Docs**: https://react.dev
- **Axios Docs**: https://axios-http.com
- **Toast Docs**: https://hot-toast.io

---

## ✅ Before Shipping to Production

- [ ] All loaders clear properly
- [ ] All errors display correctly
- [ ] No console errors
- [ ] Responsive on mobile
- [ ] Keyboard navigation works
- [ ] Touch targets are adequate (minimum 44x44px)
- [ ] Performance is acceptable
- [ ] Security checks passed

---

**Version:** 1.0.0  
**Last Updated:** April 1, 2026  
**Status:** ✅ Ready to Use
