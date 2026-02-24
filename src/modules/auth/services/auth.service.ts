import { BadRequestException, ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { AuthUser } from '../schemas/auth-schema.user';
import { Model } from 'mongoose';
import { AuthRegisterDto } from '../dto/auth-register.dto';
import bcrypt from 'bcrypt'
import { AuthVerifyDto } from '../dto/auth-verify.dto';
import { AuthResendOtpDto } from '../dto/auth-resend-verify-code.dto';
interface UpdatedData {
    email: string;
    password: string;
    otp: string;
    otpExpiresAt: Date;
    role?: string
}
@Injectable()
export class AuthService {
    constructor(@InjectModel(AuthUser.name) private authUserModel: Model<AuthUser>) { }


    // REGITER AUTH
    async authRegisterUser(authRegisterDto: AuthRegisterDto) {

        const existingUser = await this.authUserModel.findOne({
            email: authRegisterDto.email
        });

        if (existingUser) {
            throw new ConflictException('Email already exists');
        }

        const hashPassword = await bcrypt.hash(authRegisterDto.password, 12);

        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();

        const hashedVerificationCode = await bcrypt.hash(verificationCode, 12);

        const otpExpiresAt = new Date(
            Date.now() + Number(process.env.OTP_EXPIRE_MINUTES) * 60 * 1000
        );

        const newUser = await this.authUserModel.create({
            email: authRegisterDto.email,
            password: hashPassword,
            otp: hashedVerificationCode,
            otpExpiresAt,
            role: 'user'
        });

        //  Send OTP via email service (never console.log in production)
        //   await this.mailService.sendOtp(authRegisterDto.email, verificationCode);

        return {
            success: true,
            verificationCode,
            message: 'Registration successful. Please verify OTP.'
        };
    }

    // VERIFY AUTH
    async authVerify(authVerifyDto: AuthVerifyDto) {

        const user = await this.authUserModel
            .findOne({ email: authVerifyDto.email })
            .select('+otp +otpExpiresAt +otpAttempts +otpBlockedUntil');

        if (!user)
            throw new NotFoundException('User not found');

        if (user.isVerified)
            throw new BadRequestException('User is already verified');

        if (!user.otp)
            throw new BadRequestException('No OTP request found');

        if (user.otpBlockedUntil && user.otpBlockedUntil > new Date()) {
            throw new BadRequestException(
                `Too many failed attempts. Try again after ${user.otpBlockedUntil.toUTCString()}`
            );
        }

        if (!user.otpExpiresAt || user.otpExpiresAt < new Date())
            throw new BadRequestException('OTP expired');

        const isValid = await bcrypt.compare(
            authVerifyDto.otp,
            user.otp
        );

        if (!isValid) {

            const attempts = user.otpAttempts + 1;

            const updateData: any = {
                otpAttempts: attempts
            };

            if (attempts >= 5) {
                updateData.otpBlockedUntil = new Date(
                    Date.now() + Number(process.env.OTP_BLOCKED_UNTIL) * 60 * 1000
                );
                updateData.otpAttempts = 0;
            }

            await this.authUserModel.updateOne(
                { _id: user._id },
                { $set: updateData }
            );

            throw new BadRequestException('Invalid OTP');
        }

        await this.authUserModel.updateOne(
            { _id: user._id },
            {
                $set: {
                    isVerified: true,
                    otp: null,
                    otpExpiresAt: null,
                    otpAttempts: 0,
                    otpBlockedUntil: null
                }
            }
        );

        return {
            success: true,
            message: 'Account verified successfully'
        };
    }

    // RESEND VERIFICATION CODE
    async resendVerificationCode(authResendOtpDto: AuthResendOtpDto) {
        const user = await this.authUserModel
            .findOne({ email: authResendOtpDto.email })
            .select('+otp +otpExpiresAt +otpAttempts +otpBlockedUntil');

        if (!user) throw new NotFoundException('User not found');

        if (user.isVerified) throw new BadRequestException('User is already verified');

        // 🔒 Check if user is temporarily blocked from OTP
        if (user.otpBlockedUntil && user.otpBlockedUntil > new Date()) {
            throw new BadRequestException(
                `Too many failed attempts. Try again after ${user.otpBlockedUntil.toUTCString()}`
            );
        }

        // 🔹 Generate new OTP
        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        const hashedVerificationCode = await bcrypt.hash(verificationCode, 12);

        const otpExpiresAt = new Date(
            Date.now() + Number(process.env.OTP_EXPIRE_MINUTES) * 60 * 1000
        );

        // 🔹 Reset blocked info & attempts if any
        await this.authUserModel.updateOne(
            { _id: user._id },
            {
                $set: {
                    otp: hashedVerificationCode,
                    otpExpiresAt,
                    otpAttempts: 0,
                    otpBlockedUntil: null,
                },
            }
        );

        // 🔹 Send OTP via email service here (don't return real OTP in production)
        // await this.mailService.sendOtp(user.email, verificationCode);

        return {
            success: true,
            message: 'OTP sent to email successfully',
            // For dev/testing only; remove in production
            verificationCode,
        };
    }

}
