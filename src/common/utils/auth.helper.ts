import bcrypt from 'bcrypt';
import { Config } from './config';

export class AuthHelper {
  constructor(private readonly config: Config) {} // instance property

  async hashPassword(password: string): Promise<string> {
    return await bcrypt.hash(password, this.config.BCRYPT_SALT);
  }
}