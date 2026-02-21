import { Module } from '@nestjs/common';
import { SessionsController } from './controllers/sessions/sessions.controller';
import { SessionsService } from './services/sessions/sessions.service';

@Module({
  controllers: [SessionsController],
  providers: [SessionsService]
})
export class SessionsModule {}
