import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { AuthUser } from '../schemas/auth-schema.user';
import { Model } from 'mongoose';

@Injectable()
export class AuthService {
    constructor(@InjectModel(AuthUser.name) private catModel: Model<AuthUser>) { }
}