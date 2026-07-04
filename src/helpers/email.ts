async function sendEmail(apiKey: string, to: string, subject: string, html: string, text: string): Promise<boolean> {
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: 'HKGD Demon List <noreply@hkgdl.dpdns.org>', to: [to], subject, html, text }),
    });
    return res.ok;
  } catch { return false; }
}

export async function sendPasswordResetEmail(apiKey: string, to: string, resetUrl: string): Promise<boolean> {
  const subject = 'Reset Your HKGD Account Password';
  const html = `<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto">
    <h2 style="color:#e74c3c">HKGD Demon List</h2>
    <p>You requested a password reset. Click the button below — this link expires in 5 minutes.</p>
    <a href="${resetUrl}" style="display:inline-block;padding:12px 24px;background:#e74c3c;color:#fff;text-decoration:none;border-radius:6px;margin:16px 0">Reset Password</a>
    <p style="color:#888;font-size:13px">If you didn't request this, ignore this email.</p></div>`;
  const text = `Reset your HKGD password: ${resetUrl}\n\nThis link expires in 5 minutes.`;
  return sendEmail(apiKey, to, subject, html, text);
}
