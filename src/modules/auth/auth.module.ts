import { Module } from '@nestjs/common';
import { AuthController } from './controllers/auth.controller';
import { AuthService } from './services/auth.service';
import { MongooseModule } from '@nestjs/mongoose';
import { AuthUser, AuthUserSchema } from './schemas/auth-schema.user';

@Module({
  imports:[MongooseModule.forFeature([{name: AuthUser.name , schema: AuthUserSchema}])],
  controllers: [AuthController],
  providers: [AuthService]
})
export class AuthModule {}
