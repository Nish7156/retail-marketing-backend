import { Injectable, UnauthorizedException, ConflictException, BadRequestException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { CreateStoreOwnerDto } from './dto/create-store-owner.dto';
import { CreateBranchStaffDto } from './dto/create-branch-staff.dto';
import { SendOtpDto } from './dto/send-otp.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { Role } from '@prisma/client';
import { ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE } from './constants';
import { JwtPayload } from './decorators/current-user.decorator';

const OTP_EXPIRY_MINUTES = 10;
const OTP_LENGTH = 6;

function normalizePhone(phone: string): string {
  const digits = phone.replace(/\D/g, '');
  if (digits.length === 10) return `+91${digits}`;
  if (digits.length === 12 && digits.startsWith('91')) return `+${digits}`;
  return phone.startsWith('+') ? phone : `+${phone}`;
}

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async sendOtp(dto: SendOtpDto) {
    const phone = normalizePhone(dto.phone);
    const code = String(Math.floor(100000 + Math.random() * 900000));
    const expiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);
    await this.prisma.otpCode.deleteMany({ where: { phone } });
    await this.prisma.otpCode.create({
      data: { phone, code, expiresAt },
    });
    console.log(`[OTP] ${phone} => ${code} (expires ${expiresAt.toISOString()})`);
    return { ok: true, message: 'OTP sent', otp: code };
  }

  async verifyOtp(dto: VerifyOtpDto) {
    const phone = normalizePhone(dto.phone);
    const otp = await this.prisma.otpCode.findFirst({
      where: { phone, code: dto.code },
      orderBy: { createdAt: 'desc' },
    });
    if (!otp) throw new UnauthorizedException('Invalid OTP');
    if (otp.expiresAt < new Date()) {
      await this.prisma.otpCode.delete({ where: { id: otp.id } });
      throw new UnauthorizedException('OTP expired');
    }
    await this.prisma.otpCode.deleteMany({ where: { phone } });

    let user = await this.prisma.user.findUnique({
      where: { phone },
      include: { shops: { select: { id: true } }, branch: { select: { id: true } } },
    });
    if (!user) {
      user = await this.prisma.user.create({
        data: { phone, role: Role.USER },
        include: { shops: { select: { id: true } }, branch: { select: { id: true } } },
      });
    }
    const { passwordHash: _, shops, branch, ...safeUser } = user;
    const shopIds = shops.map((s) => s.id);
    const branchId = branch?.id;
    const tokens = await this.issueTokens({ ...safeUser, shopIds, branchId });
    return { user: tokens.user, accessToken: tokens.accessToken, refreshToken: tokens.refreshToken, cookieOptions: tokens.cookieOptions };
  }

  async validateUserByEmail(email: string, password: string) {
    const user = await this.prisma.user.findFirst({ where: { email } });
    if (!user || !user.passwordHash) return null;
    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) return null;
    const { passwordHash: _, ...result } = user;
    return result;
  }

  async register(dto: RegisterDto) {
    const existing = await this.prisma.user.findFirst({ where: { email: dto.email } });
    if (existing) throw new ConflictException('Email already registered');
    const passwordHash = await bcrypt.hash(dto.password, 10);
    const role = (dto.role ?? 'USER') as Role;
    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        phone: `email-${dto.email}-${Date.now()}`,
        passwordHash,
        role,
        ...(dto.shopId && { shops: { connect: { id: dto.shopId } } }),
      },
    });
    const { passwordHash: _, ...result } = user;
    return result;
  }

  async listStoreOwners() {
    return this.prisma.user.findMany({
      where: { role: Role.STORE_ADMIN },
      select: {
        id: true,
        phone: true,
        email: true,
        createdAt: true,
        shops: { select: { id: true, name: true } },
      },
      orderBy: { createdAt: 'desc' },
    });
  }

  async createStoreOwner(dto: CreateStoreOwnerDto) {
    const phone = normalizePhone(dto.phone);
    if (dto.shopId) {
      const shop = await this.prisma.shop.findUnique({ where: { id: dto.shopId } });
      if (!shop) throw new BadRequestException('Shop not found');
    }
    let user = await this.prisma.user.findUnique({
      where: { phone },
      include: { shops: { select: { id: true } } },
    });
    if (user) {
      const shopIds = user.shops.map((s) => s.id);
      const alreadyHasShop = dto.shopId && shopIds.includes(dto.shopId);
      await this.prisma.user.update({
        where: { id: user.id },
        data: {
          role: Role.STORE_ADMIN,
          ...(dto.shopId && !alreadyHasShop && { shops: { connect: { id: dto.shopId } } }),
        },
      });
      user = await this.prisma.user.findUnique({
        where: { id: user.id },
        include: { shops: { select: { id: true, name: true } } },
      })!;
    } else {
      user = await this.prisma.user.create({
        data: {
          phone,
          role: Role.STORE_ADMIN,
          ...(dto.shopId && { shops: { connect: { id: dto.shopId } } }),
        },
        include: { shops: { select: { id: true, name: true } } },
      });
    }
    const { passwordHash: _, ...result } = user as typeof user & { passwordHash?: string | null };
    return result;
  }

  async createBranchStaff(dto: CreateBranchStaffDto, currentUser: { role: string; shopIds?: string[] }) {
    if (currentUser.role !== 'SUPERADMIN' && currentUser.role !== 'STORE_ADMIN') {
      throw new UnauthorizedException('Only super admin or store admin can create branch staff');
    }
    const branch = await this.prisma.branch.findUnique({
      where: { id: dto.branchId },
      include: { shop: { select: { id: true } } },
    });
    if (!branch) throw new BadRequestException('Branch not found');
    if (currentUser.role === 'STORE_ADMIN' && !currentUser.shopIds?.includes(branch.shop.id)) {
      throw new UnauthorizedException('You can only add staff to branches of your shop(s)');
    }
    const phone = normalizePhone(dto.phone);
    let user = await this.prisma.user.findUnique({
      where: { phone },
      include: { branch: { select: { id: true } } },
    });
    if (user) {
      await this.prisma.user.update({
        where: { id: user.id },
        data: { role: Role.BRANCH_STAFF, branchId: dto.branchId },
      });
      user = await this.prisma.user.findUnique({
        where: { id: user.id },
        include: { branch: { select: { id: true, name: true, location: true, shop: { select: { name: true } } } } },
      })!;
    } else {
      user = await this.prisma.user.create({
        data: {
          phone,
          role: Role.BRANCH_STAFF,
          branchId: dto.branchId,
        },
        include: { branch: { select: { id: true, name: true, location: true, shop: { select: { name: true } } } } },
      });
    }
    const { passwordHash: _, ...result } = user as typeof user & { passwordHash?: string | null };
    return result;
  }

  async listBranchStaff(currentUser: { role: string; shopIds?: string[] }) {
    const where: { role: Role; branch?: { shopId: { in: string[] } } } = { role: Role.BRANCH_STAFF };
    if (currentUser.role === 'STORE_ADMIN' && currentUser.shopIds?.length) {
      where.branch = { shopId: { in: currentUser.shopIds } };
    }
    return this.prisma.user.findMany({
      where,
      select: {
        id: true,
        phone: true,
        email: true,
        createdAt: true,
        branch: { select: { id: true, name: true, location: true, shop: { select: { name: true } } } },
      },
      orderBy: { createdAt: 'desc' },
    });
  }

  async login(dto: LoginDto) {
    const user = await this.validateUserByEmail(dto.email, dto.password);
    if (!user) throw new UnauthorizedException('Invalid email or password');
    const withRelations = await this.prisma.user.findUnique({
      where: { id: user.id },
      include: { shops: { select: { id: true } }, branch: { select: { id: true } } },
    });
    const shopIds = withRelations?.shops.map((s) => s.id) ?? [];
    const branchId = withRelations?.branch?.id;
    const tokens = await this.issueTokens({ ...user, shopIds, branchId });
    return { user: tokens.user, accessToken: tokens.accessToken, refreshToken: tokens.refreshToken, cookieOptions: tokens.cookieOptions };
  }

  async refresh(user: JwtPayload) {
    const dbUser = await this.prisma.user.findUnique({
      where: { id: user.sub },
      include: { shops: { select: { id: true } }, branch: { select: { id: true } } },
    });
    if (!dbUser) throw new UnauthorizedException();
    const { passwordHash: _, shops, branch, ...safeUser } = dbUser;
    return this.issueTokens({
      ...safeUser,
      shopIds: shops.map((s) => s.id),
      branchId: branch?.id,
    });
  }

  async getMe(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        phone: true,
        email: true,
        role: true,
        branchId: true,
        createdAt: true,
        shops: { select: { id: true } },
        branch: { select: { id: true, name: true, location: true } },
      },
    });
    if (!user) throw new UnauthorizedException();
    const { shops, branch, ...rest } = user;
    return {
      ...rest,
      shopIds: shops.map((s) => s.id),
      branch: branch ? { id: branch.id, name: branch.name, location: branch.location } : undefined,
    };
  }

  async logout(userId: string) {
    await this.prisma.refreshToken.deleteMany({ where: { userId } });
  }

  async validateRefreshToken(userId: string, token: string): Promise<boolean> {
    const crypto = await import('crypto');
    const hash = crypto.createHash('sha256').update(token).digest('hex');
    const stored = await this.prisma.refreshToken.findFirst({
      where: { userId, tokenHash: hash },
    });
    if (!stored || stored.expiresAt < new Date()) {
      if (stored) await this.prisma.refreshToken.delete({ where: { id: stored.id } });
      return false;
    }
    return true;
  }

  private async issueTokens(user: { id: string; phone: string; email?: string | null; role: string; shopIds?: string[]; branchId?: string }) {
    const payload: JwtPayload = {
      sub: user.id,
      phone: user.phone,
      email: user.email ?? undefined,
      role: user.role,
      shopIds: user.shopIds ?? [],
      branchId: user.branchId,
    };
    const accessToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
      expiresIn: (this.configService.get<string>('JWT_ACCESS_EXPIRES_IN') ?? '1h') as any,
    });
    const refreshToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      expiresIn: (this.configService.get<string>('JWT_REFRESH_EXPIRES_IN') ?? '7d') as any,
    });
    const crypto = await import('crypto');
    const refreshHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
    const refreshExpiresIn = this.configService.get<string>('JWT_REFRESH_EXPIRES_IN') ?? '7d';
    const expiresAt = this.addTime(new Date(), refreshExpiresIn);
    await this.prisma.refreshToken.create({
      data: {
        userId: user.id,
        tokenHash: refreshHash,
        expiresAt,
      },
    });
    const cookieAccessMaxAge = parseInt(this.configService.get<string>('COOKIE_ACCESS_MAX_AGE') ?? '900', 10);
    const cookieRefreshMaxAge = parseInt(this.configService.get<string>('COOKIE_REFRESH_MAX_AGE') ?? '604800', 10);
    const isProd = this.configService.get<string>('NODE_ENV') === 'production';
    const sameSite = isProd ? ('none' as const) : ('lax' as const);
    const secure = isProd;
    return {
      accessToken,
      refreshToken,
      user: { id: user.id, phone: user.phone, email: user.email ?? undefined, role: user.role, shopIds: user.shopIds ?? [], branchId: user.branchId },
      cookieOptions: {
        access: {
          name: ACCESS_TOKEN_COOKIE,
          value: accessToken,
          maxAge: cookieAccessMaxAge,
          sameSite,
          secure,
        },
        refresh: {
          name: REFRESH_TOKEN_COOKIE,
          value: refreshToken,
          maxAge: cookieRefreshMaxAge,
          sameSite,
          secure,
        },
      },
    };
  }

  private addTime(date: Date, expiresIn: string): Date {
    const match = expiresIn.match(/^(\d+)([smhd])$/);
    if (!match) return new Date(date.getTime() + 7 * 24 * 60 * 60 * 1000);
    const [, num, unit] = match;
    const n = parseInt(num!, 10);
    const multipliers: Record<string, number> = { s: 1000, m: 60 * 1000, h: 60 * 60 * 1000, d: 24 * 60 * 60 * 1000 };
    return new Date(date.getTime() + n * (multipliers[unit!] ?? 0));
  }
}
