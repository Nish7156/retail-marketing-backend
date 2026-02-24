import { Injectable, ForbiddenException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import type { JwtPayload } from '../auth/decorators/current-user.decorator';

@Injectable()
export class BranchesService {
  constructor(private readonly prisma: PrismaService) {}

  async create(shopId: string, name: string, location: string, user: JwtPayload) {
    if (user.role === 'STORE_ADMIN' && !(user.shopIds?.includes(shopId))) {
      throw new ForbiddenException('You can only add branches to your own shop(s)');
    }
    if (user.role === 'SUPERADMIN') {
      return this.prisma.branch.create({ data: { shopId, name, location } });
    }
    const shop = await this.prisma.shop.findUnique({ where: { id: shopId } });
    if (!shop) throw new ForbiddenException('Shop not found');
    if (!user.shopIds?.includes(shopId)) throw new ForbiddenException('Shop not found');
    return this.prisma.branch.create({ data: { shopId, name, location } });
  }

  async findAll(user: JwtPayload) {
    if (user.role === 'SUPERADMIN') {
      return this.prisma.branch.findMany({
        orderBy: { createdAt: 'desc' },
        include: { shop: { select: { id: true, name: true } } },
      });
    }
    if (user.role === 'STORE_ADMIN' && user.shopIds?.length) {
      return this.prisma.branch.findMany({
        where: { shopId: { in: user.shopIds } },
        orderBy: { createdAt: 'desc' },
        include: { shop: { select: { id: true, name: true } } },
      });
    }
    return [];
  }

  async findByShop(shopId: string, user: JwtPayload) {
    if (user.role === 'SUPERADMIN') {
      return this.prisma.branch.findMany({
        where: { shopId },
        orderBy: { createdAt: 'desc' },
      });
    }
    if (user.role === 'STORE_ADMIN' && user.shopIds?.includes(shopId)) {
      return this.prisma.branch.findMany({
        where: { shopId },
        orderBy: { createdAt: 'desc' },
      });
    }
    throw new ForbiddenException();
  }
}
