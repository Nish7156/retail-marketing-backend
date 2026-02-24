import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';
import { AuthService } from '../auth.service';
import { JwtPayload } from '../decorators/current-user.decorator';
import { REFRESH_TOKEN_COOKIE } from '../constants';

@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
  constructor(
    private configService: ConfigService,
    private authService: AuthService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (req: Request) => req?.cookies?.[REFRESH_TOKEN_COOKIE] ?? null,
      ]),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_REFRESH_SECRET'),
      passReqToCallback: true,
    });
  }

  async validate(req: Request, payload: { sub: string; phone: string; email?: string; role: string; shopIds?: string[] }): Promise<JwtPayload> {
    const refreshToken = req?.cookies?.[REFRESH_TOKEN_COOKIE];
    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token missing');
    }
    const isValid = await this.authService.validateRefreshToken(payload.sub, refreshToken);
    if (!isValid) {
      throw new UnauthorizedException('Invalid refresh token');
    }
    return {
      sub: payload.sub,
      phone: payload.phone,
      email: payload.email,
      role: payload.role,
      shopIds: payload.shopIds ?? [],
    };
  }
}
