import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use(cookieParser());
  const frontendOrigin = process.env.FRONTEND_ORIGIN;
  app.enableCors({
    origin: frontendOrigin ? frontendOrigin.split(',').map((o) => o.trim()) : true,
    credentials: true,
  });
  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
