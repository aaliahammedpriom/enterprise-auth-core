import { Module } from '@nestjs/common';
import { PermissionsController } from './controllers/permissions.controller';
import { PermissionsService } from './services/permissions.service';

@Module({
  controllers: [PermissionsController],
  providers: [PermissionsService]
})
export class PermissionsModule {}
