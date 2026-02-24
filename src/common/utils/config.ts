import { number } from "zod"

export  class Config{
    BCRYPT_SALT=  Number(process.env.BCRYPT_SALT) || 5;
    
}