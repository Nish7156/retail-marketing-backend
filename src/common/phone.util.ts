import { BadRequestException } from '@nestjs/common';

const ALLOWED_PHONE_CHARS = /^[\d+\s\-]*$/;

export function validateAndNormalizePhone(phone: string): string {
  if (!ALLOWED_PHONE_CHARS.test(phone)) {
    throw new BadRequestException('Phone number must contain only numbers.');
  }
  const digits = phone.replace(/\D/g, '');
  if (digits.length === 10) return `+91${digits}`;
  if (digits.length === 12 && digits.startsWith('91')) return `+${digits}`;
  throw new BadRequestException('Invalid phone number. Use a valid 10-digit Indian number.');
}
