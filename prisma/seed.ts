import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { validateAndNormalizePhone } from '../src/common/phone.util';

const prisma = new PrismaClient();

async function main() {
  const superAdminPhone = validateAndNormalizePhone('9999999999');
  const hash = await bcrypt.hash('superadmin123', 10);
  await prisma.user.upsert({
    where: { phone: superAdminPhone },
    update: {},
    create: {
      phone: superAdminPhone,
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

  const customerPhone = validateAndNormalizePhone('9876543210');
  await prisma.customer.upsert({
    where: { id: 'seed-customer-1' },
    update: {},
    create: {
      id: 'seed-customer-1',
      name: 'John Doe',
      phone: customerPhone,
      email: 'john@example.com',
      branchId: branch.id,
    },
  });

  const storeAdminPhone = validateAndNormalizePhone('8888888888');
  await prisma.user.upsert({
    where: { phone: storeAdminPhone },
    update: {},
    create: {
      phone: storeAdminPhone,
      role: 'STORE_ADMIN',
      shops: { connect: { id: shop.id } },
    },
  });

  const branchStaffPhone = validateAndNormalizePhone('7766655555');
  await prisma.user.upsert({
    where: { phone: branchStaffPhone },
    update: {},
    create: {
      phone: branchStaffPhone,
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
