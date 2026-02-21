// src/modules/auth/dto/login.dto.ts

import { IsEmail, IsNotEmpty, IsString, MinLength } from "class-validator";

export class AuthLogin {
    @IsEmail()
    @IsNotEmpty()
    email: string;

    @IsString()
    @IsNotEmpty()
    @MinLength(6)
    password: string;
}