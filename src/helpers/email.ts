async function sendEmail(apiKey: string, to: string, subject: string, html: string, text: string): Promise<boolean> {
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: 'HKGD Demon List <hello@hkgdl.dpdns.org>',
        to: [to],
        subject,
        html,
        text,
        headers: {
          'List-Unsubscribe': `<mailto:hello@hkgdl.dpdns.org?subject=unsubscribe>`,
        },
      }),
    });
    const data = await res.json() as any;
    if (!res.ok) {
      console.error('Resend email error:', JSON.stringify(data));
      return false;
    }
    return true;
  } catch (e) {
    console.error('Email send exception:', e);
    return false;
  }
}

export async function sendPasswordResetEmail(apiKey: string, to: string, resetUrl: string, username?: string): Promise<boolean> {
  const subject = 'Reset Your HKGD Account Password';
  const name = username || 'there';
  const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Reset Your Password</title></head><body style="margin:0;padding:0;background-color:#f4f4f7;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif"><table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f4f7"><tr><td align="center" style="padding:40px 20px"><table width="100%" style="max-width:560px" cellpadding="0" cellspacing="0"><tr><td style="text-align:center;padding:0 0 20px;font-size:20px;font-weight:700;color:#a8aaaf">HKGD Demon List</td></tr><tr><td style="background-color:#fff;border-radius:8px;padding:40px 30px"><h1 style="margin:0 0 16px;font-size:22px;color:#333">Hi ${name},</h1><p style="margin:0 0 24px;font-size:16px;line-height:1.5;color:#51545e">We received a request to reset the password for your HKGD Demon List account. Click the button below to set a new password.</p><p style="margin:0 0 24px;font-size:14px;line-height:1.5;color:#51545e"><strong>This link expires in 5 minutes.</strong></p><table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:12px 0 24px"><a href="${resetUrl}" style="display:inline-block;padding:14px 32px;background-color:#3869d4;color:#fff;text-decoration:none;border-radius:6px;font-size:16px;font-weight:600">Reset Password</a></td></tr></table><p style="margin:0;font-size:14px;line-height:1.5;color:#6b6b76">If you didn't request this, you can safely ignore this email. Your password won't change until you click the link above and create a new one.</p></td></tr><tr><td style="text-align:center;padding:24px 0 0;font-size:12px;color:#a8aaaf">&copy; HKGD Demon List. <a href="mailto:hello@hkgdl.dpdns.org?subject=unsubscribe" style="color:#a8aaaf">Unsubscribe</a></td></tr></table></td></tr></table></body></html>`;
  const text = `Hi ${name},\n\nWe received a request to reset the password for your HKGD Demon List account.\n\nReset your password: ${resetUrl}\n\nThis link expires in 5 minutes.\n\nIf you didn't request this, you can safely ignore this email.\n\nTo unsubscribe, reply to this email with "unsubscribe".`;
  return sendEmail(apiKey, to, subject, html, text);
}
