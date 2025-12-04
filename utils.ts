import z from "zod";
import dotenv from "dotenv";

dotenv.config();

const schema = z.object({
  DB_HOST: z.string().nonempty(),
  DB_USER: z.string().nonempty(),
  DB_PASSWORD: z.string().nonempty(),
  DB_NAME: z.string().nonempty(),
  DB_PORT: z.string().transform(() => parseInt(process.env.DB_PORT ?? "")),
  REFRESH_SECRET: z.string().nonempty(),
});

export const env = schema.parse(process.env);

export const signupValidation = z.object({
  email: z.string().email(),
  password: z.string().min(6),
  name: z.string().min(1),
});
