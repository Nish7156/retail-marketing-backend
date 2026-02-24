import { Controller, Post, Get, Body, Res, UseGuards } from '@nestjs/common';
import type { Response } from 'express';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { CreateStoreOwnerDto } from './dto/create-store-owner.dto';
import { SendOtpDto } from './dto/send-otp.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { Public } from './decorators/public.decorator';
import { CurrentUser } from './decorators/current-user.decorator';
import type { JwtPayload } from './decorators/current-user.decorator';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { JwtRefreshGuard } from './guards/jwt-refresh.guard';
import { Roles } from './decorators/roles.decorator';
import { RolesGuard } from './guards/roles.guard';
import { ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE } from './constants';

function setAuthCookies(res: Response, cookieOptions: { access: { name: string; value: string; maxAge: number }; refresh: { name: string; value: string; maxAge: number } }) {
  const isProd = process.env.NODE_ENV === 'production';
  res.cookie(cookieOptions.access.name, cookieOptions.access.value, {
    httpOnly: true,
    secure: isProd,
    sameSite: 'lax',
    maxAge: cookieOptions.access.maxAge * 1000,
    path: '/',
  });
  res.cookie(cookieOptions.refresh.name, cookieOptions.refresh.value, {
    httpOnly: true,
    secure: isProd,
    sameSite: 'lax',
    maxAge: cookieOptions.refresh.maxAge * 1000,
    path: '/',
  });
}

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('send-otp')
  async sendOtp(@Body() dto: SendOtpDto) {
    return this.authService.sendOtp(dto);
  }

  @Public()
  @Post('verify-otp')
  async verifyOtp(@Body() dto: VerifyOtpDto, @Res({ passthrough: true }) res: Response) {
    const result = await this.authService.verifyOtp(dto);
    setAuthCookies(res, result.cookieOptions);
    return { user: result.user, accessToken: result.accessToken };
  }

  @Public()
  @Post('register')
  async register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Public()
  @Post('login')
  async login(@Body() dto: LoginDto, @Res({ passthrough: true }) res: Response) {
    const result = await this.authService.login(dto);
    setAuthCookies(res, result.cookieOptions);
    return { user: result.user, accessToken: result.accessToken };
  }

  @Public()
  @UseGuards(JwtRefreshGuard)
  @Post('refresh')
  async refresh(@CurrentUser() user: JwtPayload, @Res({ passthrough: true }) res: Response) {
    const result = await this.authService.refresh(user);
    setAuthCookies(res, result.cookieOptions);
    return { user: result.user, accessToken: result.accessToken };
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  async logout(@CurrentUser('sub') userId: string, @Res({ passthrough: true }) res: Response) {
    await this.authService.logout(userId);
    res.clearCookie(ACCESS_TOKEN_COOKIE, { path: '/' });
    res.clearCookie(REFRESH_TOKEN_COOKIE, { path: '/' });
    return { ok: true };
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  async me(@CurrentUser() user: JwtPayload) {
    const dbUser = await this.authService.getMe(user.sub);
    return dbUser;
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('SUPERADMIN')
  @Get('store-owners')
  async listStoreOwners() {
    return this.authService.listStoreOwners();
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('SUPERADMIN')
  @Post('store-owners')
  async createStoreOwner(@Body() dto: CreateStoreOwnerDto) {
    return this.authService.createStoreOwner(dto);
  }
}
