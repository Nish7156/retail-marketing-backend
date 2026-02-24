export const ROLES = {
  SUPERADMIN: 'SUPERADMIN',
  STORE_ADMIN: 'STORE_ADMIN',
  BRANCH_STAFF: 'BRANCH_STAFF',
  USER: 'USER',
} as const;

export type RoleType = keyof typeof ROLES;

export const ACCESS_TOKEN_COOKIE = 'access_token';
export const REFRESH_TOKEN_COOKIE = 'refresh_token';
