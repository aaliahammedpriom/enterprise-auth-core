import { IsEmail, IsNotEmpty, IsString } from "class-validator";
import { Transform } from "class-transformer";

export class AuthVerifyDto {
  @IsEmail({}, { message: 'Email must be valid and is required' })
  @IsNotEmpty({ message: 'Email is required' })
  @Transform(({ value }) => value?.trim())
  email: string;

  @IsString({ message: 'OTP must be a string' })
  @IsNotEmpty({ message: 'OTP is required' })
  @Transform(({ value }) => value?.trim())
  otp: string;
}