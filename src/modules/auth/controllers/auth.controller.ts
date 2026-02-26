import { Body, Controller, Get, Post, Req, Res, UseGuards, UseInterceptors } from '@nestjs/common';
import { AuthService } from '../services/auth.service';
import { AuthRegisterDto } from '../dto/auth-register.dto';
import { AuthVerifyDto } from '../dto/auth-verify.dto';
import { FileInterceptor } from '@nestjs/platform-express';
import { AuthResendOtpDto } from '../dto/auth-resend-verify-code.dto';
import { AuthLoginDto } from '../dto/auth-login.dto';
import type { Request, Response } from 'express';
import { AuthUser } from '../schemas/auth-schema.user';
import { JwtAuthGuard } from '../../../common/guards/jwt-auth.guard';
import { JwtRefreshGuard } from 'src/common/guards/jwt-refresh.guard';
interface UserWithToken extends AuthUser {
    accessToken: string;
}
@Controller('auth')
export class AuthController {

    constructor(private readonly authService: AuthService) { }
    @Post('register')
    @UseInterceptors(FileInterceptor('file'))
    authRegister(@Body() authRegisterDto: AuthRegisterDto) {
        return this.authService.authRegisterUser(authRegisterDto)
    }

    @Post('verify-auth')
    @UseInterceptors(FileInterceptor('file'))
    authVerify(@Body() authVerifyDto: AuthVerifyDto) {
        return this.authService.authVerify(authVerifyDto)
    }

    @Post('resend-verification')
    @UseInterceptors(FileInterceptor('file'))
    resendVerificationCode(@Body() authResendOtpDto: AuthResendOtpDto) {
        return this.authService.resendVerificationCode(authResendOtpDto)
    }

    @Post('login')
    @UseInterceptors(FileInterceptor('file'))
    async authLogin(@Body() authLoginDto: AuthLoginDto, @Res({ passthrough: true }) res: Response) {

        const { accessToken, refreshToken, find } = await this.authService.authLogin(authLoginDto)
        res.cookie("accessToken", accessToken, {
            httpOnly: true,
            sameSite: process.env.IS_PRODUCTION ? "none" : "lax",
            secure: process.env.IS_PRODUCTION === "production",
            path: "/",
            maxAge: process.env.ACCESS_EXPIRE_DAY as any * 24 * 60 * 60 * 1000,
        });
        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            sameSite: process.env.IS_PRODUCTION ? "none" : "lax",
            secure: process.env.IS_PRODUCTION === "production",
            path: "/",
            maxAge: process.env.REFRESH_EXPIRE_DAY as any * 24 * 60 * 60 * 1000,
        });
        const userWithToken: UserWithToken = {
            ...find.toObject(),
            accessToken,
        };

        return userWithToken
    }

    @Post('logout')
    async logout(@Res({ passthrough: true }) res: Response) {
        res.clearCookie('accessToken', {
            httpOnly: true,
            secure: process.env.IS_PRODUCTION === 'production',
            sameSite: process.env.IS_PRODUCTION ? 'none' : 'lax',
            path: '/',
        });

        res.clearCookie('refreshToken', {
            httpOnly: true,
            secure: process.env.IS_PRODUCTION === 'production',
            sameSite: process.env.IS_PRODUCTION ? 'none' : 'lax',
            path: '/',
        });

        return { message: 'Logged out successfully' };
    }

    @UseGuards(JwtRefreshGuard)
    @Post('refresh')
    async refreshToken(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
        const { accessToken, refreshToken } = await this.authService.refreshToken(req.user)

        res.cookie("accessToken", accessToken, {
            httpOnly: true,
            sameSite: process.env.IS_PRODUCTION ? "none" : "lax",
            secure: process.env.IS_PRODUCTION === "production",
            path: "/",
            maxAge: process.env.ACCESS_EXPIRE_DAY as any * 24 * 60 * 60 * 1000,
        });
        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            sameSite: process.env.IS_PRODUCTION ? "none" : "lax",
            secure: process.env.IS_PRODUCTION === "production",
            path: "/",
            maxAge: process.env.REFRESH_EXPIRE_DAY as any * 24 * 60 * 60 * 1000,
        });
        // const userWithToken: UserWithToken = {
        //     ...find.toObject(),
        //     accessToken,
        // };

        return { accessToken: accessToken }

    }


    @UseGuards(JwtAuthGuard)
    @Post('me')
    getAuthUser(@Req() req: Request) {
        console.log(req.user)
    }

}
