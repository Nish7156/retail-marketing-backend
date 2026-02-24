import { Injectable, ForbiddenException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import type { JwtPayload } from '../auth/decorators/current-user.decorator';

@Injectable()
export class OffersService {
  constructor(private readonly prisma: PrismaService) {}

  async create(
    branchId: string,
    data: { title: string; description?: string; startsAt?: Date; endsAt?: Date },
    user: JwtPayload,
  ) {
    const branch = await this.prisma.branch.findUnique({
      where: { id: branchId },
      include: { shop: true },
    });
    if (!branch) throw new ForbiddenException('Branch not found');
    if (user.role === 'STORE_ADMIN' && !user.shopIds?.includes(branch.shopId)) {
      throw new ForbiddenException('You can only create offers for your shop branches');
    }
    return this.prisma.offer.create({
      data: {
        branchId,
        title: data.title,
        description: data.description ?? null,
        startsAt: data.startsAt ?? null,
        endsAt: data.endsAt ?? null,
      },
    });
  }

  async findAll(user: JwtPayload) {
    if (user.role === 'SUPERADMIN') {
      return this.prisma.offer.findMany({
        orderBy: { createdAt: 'desc' },
        include: { branch: { include: { shop: { select: { id: true, name: true } } } } },
      });
    }
    if (user.role === 'STORE_ADMIN' && user.shopIds?.length) {
      return this.prisma.offer.findMany({
        where: { branch: { shopId: { in: user.shopIds } } },
        orderBy: { createdAt: 'desc' },
        include: { branch: { include: { shop: { select: { id: true, name: true } } } } },
      });
    }
    return [];
  }

  async findByBranch(branchId: string, user: JwtPayload) {
    const branch = await this.prisma.branch.findUnique({ where: { id: branchId } });
    if (!branch) throw new ForbiddenException('Branch not found');
    if (user.role === 'STORE_ADMIN' && !user.shopIds?.includes(branch.shopId)) {
      throw new ForbiddenException();
    }
    return this.prisma.offer.findMany({
      where: { branchId },
      orderBy: { createdAt: 'desc' },
      include: { branch: { select: { id: true, name: true, location: true } } },
    });
  }
}
