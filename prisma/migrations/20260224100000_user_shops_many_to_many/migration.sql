-- CreateTable (Prisma implicit many-to-many: Shop + User)
CREATE TABLE "_ShopToUser" (
    "A" TEXT NOT NULL,
    "B" TEXT NOT NULL
);

-- Migrate existing User.shop_id into join table
INSERT INTO "_ShopToUser" ("A", "B")
SELECT "shop_id", "id" FROM "User" WHERE "shop_id" IS NOT NULL;

-- CreateIndex
CREATE UNIQUE INDEX "_ShopToUser_AB_unique" ON "_ShopToUser"("A", "B");
CREATE INDEX "_ShopToUser_B_index" ON "_ShopToUser"("B");

-- DropForeignKey
ALTER TABLE "User" DROP CONSTRAINT IF EXISTS "User_shop_id_fkey";

-- DropColumn
ALTER TABLE "User" DROP COLUMN IF EXISTS "shop_id";

-- AddForeignKey
ALTER TABLE "_ShopToUser" ADD CONSTRAINT "_ShopToUser_A_fkey" FOREIGN KEY ("A") REFERENCES "Shop"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "_ShopToUser" ADD CONSTRAINT "_ShopToUser_B_fkey" FOREIGN KEY ("B") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
