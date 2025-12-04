"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.signupValidation = exports.env = void 0;
const zod_1 = __importDefault(require("zod"));
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
const schema = zod_1.default.object({
    DB_HOST: zod_1.default.string().nonempty(),
    DB_USER: zod_1.default.string().nonempty(),
    DB_PASSWORD: zod_1.default.string().nonempty(),
    DB_NAME: zod_1.default.string().nonempty(),
    DB_PORT: zod_1.default.string().transform(() => { var _a; return parseInt((_a = process.env.DB_PORT) !== null && _a !== void 0 ? _a : ""); }),
    REFRESH_SECRET: zod_1.default.string().nonempty(),
});
exports.env = schema.parse(process.env);
exports.signupValidation = zod_1.default.object({
    email: zod_1.default.string().email(),
    password: zod_1.default.string().min(6),
    name: zod_1.default.string().min(1),
});
