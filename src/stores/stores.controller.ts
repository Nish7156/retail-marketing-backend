import { Controller, Get, Post, Body, UseGuards } from '@nestjs/common';
import { StoresService } from './stores.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';

@Controller('stores')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('SUPERADMIN')
export class StoresController {
  constructor(private readonly storesService: StoresService) {}

  @Post()
  create(@Body() body: { name: string }) {
    return this.storesService.create(body.name);
  }

  @Get()
  findAll() {
    return this.storesService.findAll();
  }
}
