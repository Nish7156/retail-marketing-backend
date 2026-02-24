import { Injectable, UnauthorizedException, ConflictException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { CreateStoreOwnerDto } from './dto/create-store-owner.dto';
import { Role } from '@prisma/client';
import { ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE } from './constants';
import { JwtPayload } from './decorators/current-user.decorator';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async validateUser(email: string, password: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) return null;
    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) return null;
    const { passwordHash: _, ...result } = user;
    return result;
  }

  async register(dto: RegisterDto) {
    const existing = await this.prisma.user.findUnique({ where: { email: dto.email } });
    if (existing) throw new ConflictException('Email already registered');
    const passwordHash = await bcrypt.hash(dto.password, 10);
    const role = (dto.role ?? 'USER') as Role;
    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        passwordHash,
        role,
        storeId: dto.storeId ?? null,
      },
    });
    const { passwordHash: _, ...result } = user;
    return result;
  }

  async listStoreOwners() {
    return this.prisma.user.findMany({
      where: { role: Role.STORE_ADMIN },
      select: { id: true, email: true, storeId: true, createdAt: true },
      orderBy: { createdAt: 'desc' },
    });
  }

  async createStoreOwner(dto: CreateStoreOwnerDto) {
    const existing = await this.prisma.user.findUnique({ where: { email: dto.email } });
    if (existing) throw new ConflictException('Email already registered');
    if (dto.storeId) {
      const store = await this.prisma.store.findUnique({ where: { id: dto.storeId } });
      if (!store) throw new ConflictException('Store not found');
    }
    const passwordHash = await bcrypt.hash(dto.password, 10);
    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        passwordHash,
        role: Role.STORE_ADMIN,
        storeId: dto.storeId ?? null,
      },
    });
    const { passwordHash: _, ...result } = user;
    return result;
  }

  async login(dto: LoginDto) {
    const user = await this.validateUser(dto.email, dto.password);
    if (!user) throw new UnauthorizedException('Invalid email or password');
    const tokens = await this.issueTokens(user);
    return { user: tokens.user, accessToken: tokens.accessToken, refreshToken: tokens.refreshToken, cookieOptions: tokens.cookieOptions };
  }

  async refresh(user: JwtPayload) {
    const dbUser = await this.prisma.user.findUnique({ where: { id: user.sub } });
    if (!dbUser) throw new UnauthorizedException();
    const { passwordHash: _, ...safeUser } = dbUser;
    return this.issueTokens(safeUser);
  }

  async getMe(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, email: true, role: true, storeId: true, createdAt: true },
    });
    if (!user) throw new UnauthorizedException();
    return user;
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

  private async issueTokens(user: { id: string; email: string; role: string; storeId?: string | null }) {
    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      role: user.role,
      storeId: user.storeId ?? undefined,
    };
    const accessToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
      expiresIn: this.configService.get<string>('JWT_ACCESS_EXPIRES_IN'),
    });
    const refreshToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      expiresIn: this.configService.get<string>('JWT_REFRESH_EXPIRES_IN'),
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
    return {
      accessToken,
      refreshToken,
      user: { id: user.id, email: user.email, role: user.role, storeId: user.storeId },
      cookieOptions: {
        access: {
          name: ACCESS_TOKEN_COOKIE,
          value: accessToken,
          maxAge: cookieAccessMaxAge,
        },
        refresh: {
          name: REFRESH_TOKEN_COOKIE,
          value: refreshToken,
          maxAge: cookieRefreshMaxAge,
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
