import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
  const hash = await bcrypt.hash('superadmin123', 10);
  await prisma.user.upsert({
    where: { email: 'superadmin@retail.com' },
    update: {},
    create: {
      email: 'superadmin@retail.com',
      passwordHash: hash,
      role: 'SUPERADMIN',
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
