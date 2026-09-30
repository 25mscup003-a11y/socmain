const nodemailer = require('nodemailer');

const smtpPort = parseInt(process.env.SMTP_PORT || '587', 10);
const smtpSecure = process.env.SMTP_SECURE
  ? process.env.SMTP_SECURE === 'true'
  : smtpPort === 465;

// Create transporter using SMTP configuration
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: smtpPort,
  secure: smtpSecure,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// Generate 6-digit OTP
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Send OTP via email
const sendOTP = async (email, otp, userName = '') => {
  try {
    const mailOptions = {
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: email,
      subject: 'Your Spartan Cyber Defense Center (SCDC) Verification Code',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; color: white; border-radius: 8px 8px 0 0;">
            <h2 style="margin: 0;">Spartan Cyber Defense Center (SCDC)</h2>
          </div>
          <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px; border: 1px solid #e0e0e0;">
            <p style="color: #333; margin-bottom: 20px;">
              Hello ${userName || 'User'},
            </p>
            <p style="color: #666; margin-bottom: 25px;">
              Your OTP for email verification is:
            </p>
            <div style="background: white; border: 2px solid #667eea; padding: 20px; text-align: center; border-radius: 8px; margin: 20px 0;">
              <h1 style="color: #667eea; margin: 0; letter-spacing: 5px; font-size: 32px;">${otp}</h1>
            </div>
            <p style="color: #666; margin: 20px 0; font-size: 14px;">
              This OTP is valid for 10 minutes only. Do not share this code with anyone.
            </p>
            <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 25px 0;">
            <p style="color: #999; font-size: 12px; margin: 0;">
              If you did not request this verification, please ignore this email.
            </p>
          </div>
        </div>
      `,
    };

    const result = await transporter.sendMail(mailOptions);
    console.log('OTP sent to:', email);
    return result;
  } catch (err) {
    console.error('Failed to send OTP:', err);
    throw new Error('Failed to send OTP email');
  }
};

module.exports = { generateOTP, sendOTP };
