// src/modules/auth/schemas/auth-user.schema.ts
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';
import { AuthUserRole, AuthUserStatus } from './auth-enum.user';

export type AuthUserDocument = HydratedDocument<AuthUser>;

@Schema({ timestamps: true })
export class AuthUser {
  @Prop({ type: String, required: true, unique: true })
  email: string;

  @Prop({ type: String, required: true, default: AuthUserRole.Student })
  role: string;

  @Prop({ type: String, required: true, select: false })
  password: string;

  @Prop({ type: String, default: AuthUserStatus.Active })
  status: string;

  @Prop({ type: Boolean, default: false, select: false })
  otp: boolean;

  @Prop({ type: Date, default: null, select: false })
  otpExpiresAt: Date;

  @Prop({ type: Boolean, default: false, select: false })
  isOtpVerified: boolean;

  @Prop({ type: String, default: null, select: false })
  refreshToken: string;

  @Prop({ type: Date, default: null, select: false })
  passwordChangedAt: Date;

  @Prop({ type: Boolean, default: false })
  isVerified: boolean;

  @Prop({ type: String, default: null, select: false })
  verificationToken: string;

  @Prop({ type: Date, default: null, select: false })
  verificationExpiresAt: Date;

  @Prop({ type: Boolean, default: false })
  isDeleted: boolean;
}

export const AuthUserSchema = SchemaFactory.createForClass(AuthUser);

// Optional: indexes for fast lookup
AuthUserSchema.index({ email: 1 });
AuthUserSchema.index({ role: 1 });
AuthUserSchema.index({ status: 1 });