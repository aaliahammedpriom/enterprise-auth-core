import { Module } from '@nestjs/common';
import { AuditController } from './controllers/audit/audit.controller';
import { AuditService } from './services/audit/audit.service';

@Module({
  controllers: [AuditController],
  providers: [AuditService]
})
export class AuditModule {}
