-- AlterEnum
ALTER TYPE "Role" ADD VALUE 'BRANCH_STAFF';

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "branch_id" TEXT;

-- AlterTable
ALTER TABLE "_ShopToUser" ADD CONSTRAINT "_ShopToUser_AB_pkey" PRIMARY KEY ("A", "B");

-- DropIndex
DROP INDEX "_ShopToUser_AB_unique";

-- CreateTable
CREATE TABLE "Customer" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "phone" TEXT NOT NULL,
    "email" TEXT,
    "branch_id" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Customer_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Customer_branch_id_idx" ON "Customer"("branch_id");

-- AddForeignKey
ALTER TABLE "User" ADD CONSTRAINT "User_branch_id_fkey" FOREIGN KEY ("branch_id") REFERENCES "Branch"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Customer" ADD CONSTRAINT "Customer_branch_id_fkey" FOREIGN KEY ("branch_id") REFERENCES "Branch"("id") ON DELETE CASCADE ON UPDATE CASCADE;
