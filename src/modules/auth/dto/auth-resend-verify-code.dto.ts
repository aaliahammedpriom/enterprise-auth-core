import { Transform } from "class-transformer";
import { IsEmail, IsNotEmpty } from "class-validator";

export class AuthResendOtpDto{
    @IsEmail({}, { message: 'Email must be valid and is required' })
    @IsNotEmpty({ message: 'Email is required' })
    @Transform(({ value }) => value?.trim())
    email: string;
}