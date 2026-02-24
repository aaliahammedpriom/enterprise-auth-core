import { Module } from '@nestjs/common';
import { AuthModule } from './modules/auth/auth.module';
import { UsersModule } from './modules/users/users.module';
import { RolesModule } from './modules/roles/roles.module';
import { PermissionsModule } from './modules/permissions/permissions.module';
import { SessionsModule } from './modules/sessions/sessions.module';
import { AuditModule } from './modules/audit/audit.module';
import { ConfigModule } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';

@Module({
  imports: [
     ConfigModule.forRoot({
      isGlobal: true,
    }),
    MongooseModule.forRoot(process.env.MONGODB_URL as string),
    AuthModule, UsersModule, RolesModule, PermissionsModule, SessionsModule, AuditModule],
  controllers: [],
  providers: [],
})
export class AppModule { }
