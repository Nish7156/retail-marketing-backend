import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class StoresService {
  constructor(private readonly prisma: PrismaService) {}

  create(name: string) {
    return this.prisma.store.create({ data: { name } });
  }

  findAll() {
    return this.prisma.store.findMany({ orderBy: { createdAt: 'desc' } });
  }
}
