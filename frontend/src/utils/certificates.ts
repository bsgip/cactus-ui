import type { CertificateResponse } from '../api/types';

// Certificates expiring within this window get flagged so users regenerate before tests fail.
export const CERT_EXPIRY_WARNING_DAYS = 30;

export type CertificateExpiryStatus = 'expired' | 'expiring' | 'valid';

export function certTypeLabel(isDeviceCert: boolean): 'Device' | 'Aggregator' {
  return isDeviceCert ? 'Device' : 'Aggregator';
}

export function certExpiryStatus(
  expiresAt: string,
  now: Date = new Date()
): CertificateExpiryStatus {
  const expires = new Date(expiresAt).getTime();
  if (expires <= now.getTime()) return 'expired';
  if (expires - now.getTime() <= CERT_EXPIRY_WARNING_DAYS * 24 * 60 * 60 * 1000) return 'expiring';
  return 'valid';
}

export function formatCertDate(value: string): string {
  return new Date(value).toLocaleDateString('sv'); // YYYY-MM-DD
}

// "Battery Mk1 device (Device)" - used wherever a certificate is offered as a choice.
export function certificateLabel(cert: CertificateResponse): string {
  return `${cert.name} (${certTypeLabel(cert.is_device_cert)})`;
}
