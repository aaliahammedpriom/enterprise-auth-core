import { Body, Controller, Post, UseInterceptors } from '@nestjs/common';
import { AuthService } from '../services/auth.service';
import { AuthRegisterDto } from '../dto/auth-register.dto';
import { AuthVerifyDto } from '../dto/auth-verify.dto';
import { FileInterceptor } from '@nestjs/platform-express';
import { AuthResendOtpDto } from '../dto/auth-resend-verify-code.dto';

@Controller('auth')
export class AuthController {

    constructor(private readonly authService: AuthService) { }
    @Post('register')
    @UseInterceptors(FileInterceptor('file'))
    authRegister(@Body() authRegisterDto: AuthRegisterDto) {
        const result = this.authService.authRegisterUser(authRegisterDto)
        return result
    }

    @Post('verify-auth')
    @UseInterceptors(FileInterceptor('file'))
    authVerify(@Body() authVerifyDto: AuthVerifyDto) {
        const result = this.authService.authVerify(authVerifyDto)
        return result
    }
    @Post('resend-verification')
    @UseInterceptors(FileInterceptor('file'))
    resendVerificationCode(@Body() authResendOtpDto: AuthResendOtpDto) {
        const result = this.authService.resendVerificationCode(authResendOtpDto)
        return result
    }
}
