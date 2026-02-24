import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import compression from 'compression';
import helmet from 'helmet';
import cookieParser = require('cookie-parser'); 

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Security middleware
  app.use(helmet());
  app.use(compression());

  // Enable CORS
  app.enableCors({ origin: '*', credentials: true });

  // Global validation
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    })
  );

  // Cookie parser
  app.use(cookieParser());

  const port = process.env.PORT ?? 3000;
  await app.listen(port);

  console.log(
    `Server running at http://localhost:${port} | ${new Date().toLocaleString('en-US', { hour12: true, timeZone: 'Asia/Dhaka' })}`
  );
}
bootstrap();