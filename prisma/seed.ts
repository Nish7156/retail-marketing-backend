import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
  const hash = await bcrypt.hash('superadmin123', 10);
  await prisma.user.upsert({
    where: { phone: '+919999999999' },
    update: {},
    create: {
      phone: '+919999999999',
      email: 'superadmin@retail.com',
      passwordHash: hash,
      role: 'SUPERADMIN',
    },
  });

  const shop = await prisma.shop.upsert({
    where: { id: 'seed-shop-1' },
    update: {},
    create: {
      id: 'seed-shop-1',
      name: 'Main Store',
    },
  });

  const branch = await prisma.branch.upsert({
    where: { id: 'seed-branch-1' },
    update: {},
    create: {
      id: 'seed-branch-1',
      name: 'Downtown',
      location: '123 Main St',
      shopId: shop.id,
    },
  });

  await prisma.offer.upsert({
    where: { id: 'seed-offer-1' },
    update: {},
    create: {
      id: 'seed-offer-1',
      title: '20% Off',
      description: 'First purchase discount',
      branchId: branch.id,
    },
  });

  await prisma.customer.upsert({
    where: { id: 'seed-customer-1' },
    update: {},
    create: {
      id: 'seed-customer-1',
      name: 'John Doe',
      phone: '+917777777777',
      email: 'john@example.com',
      branchId: branch.id,
    },
  });

  await prisma.user.upsert({
    where: { phone: '+918888888888' },
    update: {},
    create: {
      phone: '+918888888888',
      role: 'STORE_ADMIN',
      shops: { connect: { id: shop.id } },
    },
  });

  await prisma.user.upsert({
    where: { phone: '+917766665555' },
    update: {},
    create: {
      phone: '+917766665555',
      role: 'BRANCH_STAFF',
      branchId: branch.id,
    },
  });
}

main()
  .then(() => prisma.$disconnect())
  .catch((e) => {
    console.error(e);
    prisma.$disconnect();
    process.exit(1);
  });
