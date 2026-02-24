import { Transform } from "class-transformer";
import { IsEmail, IsNotEmpty, IsString, Matches, MinLength } from "class-validator";

export class AuthLoginDto {
    @IsEmail({}, { message: 'Email must be valid and is required' })
    @IsNotEmpty({ message: 'Email must be required' })
    @Transform(({ value }) => value?.trim())
    email: string;

    @IsString({ message: 'Password must be a string' })
    @IsNotEmpty({ message: 'Password is required' })
    @MinLength(8, { message: 'Password must be at least 8 characters long' })
    @Matches(/[a-z]/, { message: 'Password must contain at least one lowercase letter', })
    @Matches(/[A-Z]/, { message: 'Password must contain at least one uppercase letter', })
    @Matches(/\d/, { message: 'Password must contain at least one number', })
    @Matches(/[@$!%*?&]/, { message: 'Password must contain at least one special character (@$!%*?&)', })
    @Transform(({ value }) => value?.trim())
    password: string;
}