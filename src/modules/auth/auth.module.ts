import { Module } from '@nestjs/common';
import { AuthController } from './controllers/auth.controller';
import { AuthService } from './services/auth.service';
import { MongooseModule } from '@nestjs/mongoose';
import { AuthUser, AuthUserSchema } from './schemas/auth-schema.user';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { StringValue } from 'ms';
import { JwtStrategy } from './strategies/jwt-access.strategy';
import { PassportModule } from '@nestjs/passport';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { JwtRefreshGuard } from 'src/common/guards/jwt-refresh.guard';
import { JwtRefreshStrategy } from './strategies/jwt-refresh.strategy';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),

    MongooseModule.forFeature([
      { name: AuthUser.name, schema: AuthUserSchema }
    ]),

    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>('ACCESS_SECRET'),
        signOptions: {
          expiresIn: config.get<StringValue>('ACCESS_EXPIRE') || '5m' ,
        },
      }),
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy,JwtAuthGuard,JwtRefreshGuard, JwtRefreshStrategy],
})
export class AuthModule { }