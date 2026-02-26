import { ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";

@Injectable()
export class JwtRefreshGuard extends AuthGuard('refresh') {
    handleRequest<TUser = any>(err: any, user: any, info: any, context: ExecutionContext, status?: any): TUser {
        if (err || !user) {
            throw new UnauthorizedException('Invalid refresh token')
        }
        return user
    }
}