import { Injectable, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { validateAndNormalizePhone } from '../common/phone.util';

@Injectable()
export class ShopsService {
  constructor(private readonly prisma: PrismaService) {}

  create(name: string) {
    return this.prisma.shop.create({ data: { name } });
  }

  findAll() {
    return this.prisma.shop.findMany({
      orderBy: { createdAt: 'desc' },
      include: { _count: { select: { branches: true, users: true } } },
    });
  }

  findOne(id: string) {
    return this.prisma.shop.findUnique({
      where: { id },
      include: { branches: true, users: { select: { id: true, phone: true, email: true, role: true } } },
    });
  }

  async addOwner(shopId: string, userId: string) {
    const shop = await this.prisma.shop.findUnique({ where: { id: shopId } });
    if (!shop) throw new BadRequestException('Shop not found');
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new BadRequestException('User not found');
    await this.prisma.shop.update({
      where: { id: shopId },
      data: { users: { connect: { id: userId } } },
    });
    return { ok: true, message: 'Owner added to shop' };
  }

  async addOwnerByPhone(shopId: string, phone: string) {
    const shop = await this.prisma.shop.findUnique({ where: { id: shopId } });
    if (!shop) throw new BadRequestException('Shop not found');
    const normalizedPhone = validateAndNormalizePhone(phone);
    const user = await this.prisma.user.findUnique({ where: { phone: normalizedPhone } });
    if (!user) throw new BadRequestException('User not found');
    await this.prisma.shop.update({
      where: { id: shopId },
      data: { users: { connect: { id: user.id } } },
    });
    return { ok: true, message: 'Owner added to shop' };
  }
}
