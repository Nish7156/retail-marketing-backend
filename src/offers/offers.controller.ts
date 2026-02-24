import { Controller, Get, Post, Body, Param, UseGuards } from '@nestjs/common';
import { OffersService } from './offers.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import type { JwtPayload } from '../auth/decorators/current-user.decorator';

@Controller('offers')
@UseGuards(JwtAuthGuard, RolesGuard)
export class OffersController {
  constructor(private readonly offersService: OffersService) {}

  @Post()
  @Roles('SUPERADMIN', 'STORE_ADMIN')
  create(
    @Body() body: { branchId: string; title: string; description?: string; startsAt?: string; endsAt?: string },
    @CurrentUser() user: JwtPayload,
  ) {
    const startsAt = body.startsAt ? new Date(body.startsAt) : undefined;
    const endsAt = body.endsAt ? new Date(body.endsAt) : undefined;
    return this.offersService.create(
      body.branchId,
      { title: body.title, description: body.description, startsAt, endsAt },
      user,
    );
  }

  @Get()
  @Roles('SUPERADMIN', 'STORE_ADMIN')
  findAll(@CurrentUser() user: JwtPayload) {
    return this.offersService.findAll(user);
  }

  @Get('branch/:branchId')
  @Roles('SUPERADMIN', 'STORE_ADMIN')
  findByBranch(@Param('branchId') branchId: string, @CurrentUser() user: JwtPayload) {
    return this.offersService.findByBranch(branchId, user);
  }
}
