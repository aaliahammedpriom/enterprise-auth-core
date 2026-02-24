import { Injectable, UnauthorizedException } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { Strategy, ExtractJwt } from "passport-jwt";
import { ConfigService } from "@nestjs/config";
import { InjectModel } from "@nestjs/mongoose";
import { AuthUser } from "../schemas/auth-schema.user";
import { Model } from "mongoose";
import { Request } from "express";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
    constructor(
        @InjectModel(AuthUser.name) private authUserModel: Model<AuthUser>,
        private configService: ConfigService
    ) {

        const secret = configService.get<string>('ACCESS_SECRET');
        if (!secret) throw new Error('ACCESS_SECRET not defined');
        super({
            // jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            jwtFromRequest: (req: Request) => {
                if (!req || !req.cookies) return null;
                const token = req.cookies['accessToken'];
                return token;
            },
            secretOrKey: secret,
            ignoreExpiration: false,
        });
    }

    async validate(payload: { _id: string; email: string; role: string }) {
        const user = await this.authUserModel.findById(payload._id);
        if (!user) throw new UnauthorizedException('User not found');
        if (user.status === 'blocked') throw new UnauthorizedException('User blocked');
        if (user.isDeleted) throw new UnauthorizedException('User deleted');
        return user;
    }
}