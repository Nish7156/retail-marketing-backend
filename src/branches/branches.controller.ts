import { Controller, Get, Post, Body, Param, UseGuards } from '@nestjs/common';
import { BranchesService } from './branches.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import type { JwtPayload } from '../auth/decorators/current-user.decorator';

@Controller('branches')
@UseGuards(JwtAuthGuard, RolesGuard)
export class BranchesController {
  constructor(private readonly branchesService: BranchesService) {}

  @Post()
  @Roles('SUPERADMIN', 'STORE_ADMIN')
  create(
    @Body() body: { shopId: string; name: string; location: string },
    @CurrentUser() user: JwtPayload,
  ) {
    return this.branchesService.create(body.shopId, body.name, body.location, user);
  }

  @Get()
  @Roles('SUPERADMIN', 'STORE_ADMIN')
  findAll(@CurrentUser() user: JwtPayload) {
    return this.branchesService.findAll(user);
  }

  @Get('shop/:shopId')
  @Roles('SUPERADMIN', 'STORE_ADMIN')
  findByShop(@Param('shopId') shopId: string, @CurrentUser() user: JwtPayload) {
    return this.branchesService.findByShop(shopId, user);
  }
}
