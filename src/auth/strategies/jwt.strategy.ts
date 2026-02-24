import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { JwtPayload } from '../decorators/current-user.decorator';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(private configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (req) => req?.cookies?.access_token ?? ExtractJwt.fromAuthHeaderAsBearerToken()(req),
      ]),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_ACCESS_SECRET'),
    });
  }

  async validate(payload: { sub: string; phone: string; email?: string; role: string; shopIds?: string[] }): Promise<JwtPayload> {
    if (!payload.sub || !payload.phone) {
      throw new UnauthorizedException();
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
