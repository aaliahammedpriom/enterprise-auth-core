import { Injectable, Req, UnauthorizedException } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { PassportStrategy } from "@nestjs/passport";
import { Strategy } from "passport-jwt";
import { AuthUser } from "../schemas/auth-schema.user";
import { Model } from "mongoose";
import { ConfigService } from "@nestjs/config";
import { Request } from "express";
import bcrypt from 'bcrypt'

@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(Strategy, 'refresh') {
    constructor(
        @InjectModel(AuthUser.name) private authUserModel: Model<AuthUser>,
        private configService: ConfigService
    ) {
        const secret = configService.get<string>('REFRESH_SECRET')
        if (!secret) throw new Error('REFRESH_SECRET not defined');
        super({
            // jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            jwtFromRequest: (req: Request) => {
                if (!req || !req.cookies) return null;
                const token = req.cookies['refreshToken'];
                return token;
            },
            secretOrKey: secret,
            ignoreExpiration: false,
            passReqToCallback: true
        });

    }
    async validate( req:Request, payload: { _id: string; email: string; role: string }) {
        if(!req.cookies.refreshToken) throw new UnauthorizedException('Refresh token not found')
        const user = await this.authUserModel.findById(payload._id).select('+refreshToken');
        if (!user) throw new UnauthorizedException('User not found');
        if (user.status === 'blocked') throw new UnauthorizedException('User blocked');
        if (user.isDeleted) throw new UnauthorizedException('User deleted');
        const isMatch = await bcrypt.compare(req.cookies.refreshToken , user.refreshToken)
        if(!isMatch) throw new UnauthorizedException("Invalid Refresh Token")
        return user;
    }

}