export function loadRazorpay() {
  return new Promise((resolve, reject) => {
    if (window.Razorpay) return resolve(window.Razorpay);
    const script = document.createElement('script');
    script.src   = 'https://checkout.razorpay.com/v1/checkout.js';
    script.async = true;
    script.onload  = () => resolve(window.Razorpay);
    script.onerror = () => reject(new Error('Failed to load Razorpay SDK'));
    document.body.appendChild(script);
  });
}

export async function openRazorpay({ order, subscription, planLabel, email, phone, onSuccess, onFailure }) {
  const RazorpayClass = await loadRazorpay();
  const isSubscription = Boolean(subscription?.id);
  const options = {
    key:         import.meta.env.VITE_RAZORPAY_KEY,
    ...(!isSubscription ? { amount: order.amount } : {}),
    currency:    subscription?.currency || order?.currency || 'INR',
    name:        'Spartan Cyber Defense Center (SCDC)',
    description: planLabel,
    ...(isSubscription ? { subscription_id: subscription.id } : { order_id: order.id }),
    prefill:     { email: email || '', contact: phone || '' },
    theme:       { color: '#2563eb' },
    handler:     (response) => { if (onSuccess) onSuccess(response); },
  };
  const rzp = new RazorpayClass(options);
  rzp.on('payment.failed', r => { if (onFailure) onFailure(r.error?.description || 'Payment failed'); });
  rzp.open();
}
