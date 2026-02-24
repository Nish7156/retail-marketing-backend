import { Injectable, ForbiddenException, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import type { JwtPayload } from '../auth/decorators/current-user.decorator';
import { CreateCustomerDto } from './dto/create-customer.dto';

@Injectable()
export class CustomersService {
  constructor(private readonly prisma: PrismaService) {}

  private async canAccessBranch(branchId: string, user: JwtPayload): Promise<boolean> {
    if (user.role === 'SUPERADMIN') return true;
    if (user.role === 'BRANCH_STAFF' && user.branchId === branchId) return true;
    if (user.role === 'STORE_ADMIN' && user.shopIds?.length) {
      const branch = await this.prisma.branch.findUnique({
        where: { id: branchId },
        select: { shopId: true },
      });
      return branch ? user.shopIds.includes(branch.shopId) : false;
    }
    return false;
  }

  async create(dto: CreateCustomerDto, user: JwtPayload) {
    const can = await this.canAccessBranch(dto.branchId, user);
    if (!can) throw new ForbiddenException('You cannot add customers to this branch');
    const branch = await this.prisma.branch.findUnique({ where: { id: dto.branchId } });
    if (!branch) throw new BadRequestException('Branch not found');
    return this.prisma.customer.create({
      data: {
        branchId: dto.branchId,
        name: dto.name,
        phone: dto.phone,
        email: dto.email,
      },
      include: { branch: { select: { id: true, name: true, location: true } } },
    });
  }

  async findAll(user: JwtPayload, branchId?: string) {
    if (user.role === 'BRANCH_STAFF') {
      const id = user.branchId;
      if (!id) return [];
      return this.prisma.customer.findMany({
        where: { branchId: id },
        orderBy: { createdAt: 'desc' },
        include: { branch: { select: { id: true, name: true, location: true } } },
      });
    }
    if (user.role === 'STORE_ADMIN' && user.shopIds?.length) {
      const where: { branchId?: string; branch?: { shopId: { in: string[] } } } = {
        branch: { shopId: { in: user.shopIds } },
      };
      if (branchId) where.branchId = branchId;
      return this.prisma.customer.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        include: { branch: { select: { id: true, name: true, location: true, shop: { select: { name: true } } } } },
      });
    }
    if (user.role === 'SUPERADMIN') {
      const where = branchId ? { branchId } : {};
      return this.prisma.customer.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        include: { branch: { select: { id: true, name: true, location: true, shop: { select: { name: true } } } } },
      });
    }
    return [];
  }
}
