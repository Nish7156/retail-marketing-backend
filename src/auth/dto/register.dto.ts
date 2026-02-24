export class RegisterDto {
  email: string;
  password: string;
  role?: 'SUPERADMIN' | 'STORE_ADMIN' | 'USER';
  shopId?: string;
}
