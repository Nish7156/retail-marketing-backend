import { Controller, Get, Post, Body, Param, UseGuards, BadRequestException } from '@nestjs/common';
import { ShopsService } from './shops.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';

@Controller('shops')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('SUPERADMIN')
export class ShopsController {
  constructor(private readonly shopsService: ShopsService) {}

  @Post()
  create(@Body() body: { name: string }) {
    return this.shopsService.create(body.name);
  }

  @Get()
  findAll() {
    return this.shopsService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.shopsService.findOne(id);
  }

  @Post(':id/owners')
  addOwner(
    @Param('id') shopId: string,
    @Body() body: { userId?: string; phone?: string },
  ) {
    if (body.userId) return this.shopsService.addOwner(shopId, body.userId);
    if (body.phone) return this.shopsService.addOwnerByPhone(shopId, body.phone);
    throw new BadRequestException('Provide userId or phone');
  }
}
