import { Controller, Get, Post, Body, Query, UseGuards } from '@nestjs/common';
import { CustomersService } from './customers.service';
import { CreateCustomerDto } from './dto/create-customer.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import type { JwtPayload } from '../auth/decorators/current-user.decorator';

@Controller('customers')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('SUPERADMIN', 'STORE_ADMIN', 'BRANCH_STAFF')
export class CustomersController {
  constructor(private readonly customersService: CustomersService) {}

  @Post()
  create(@Body() dto: CreateCustomerDto, @CurrentUser() user: JwtPayload) {
    return this.customersService.create(dto, user);
  }

  @Get()
  findAll(@CurrentUser() user: JwtPayload, @Query('branchId') branchId?: string) {
    return this.customersService.findAll(user, branchId);
  }
}
