import bcrypt from "bcryptjs";
import { SignJWT, jwtVerify, JWTPayload } from "jose";

export async function hashPassword(password: string): Promise<string> {
    const hash = await bcrypt.hash(password, 10);
    return hash;
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
    const isMatch = await bcrypt.compare(password, hash);
    return isMatch;
}

export interface SessionPayload extends JWTPayload {
    userId: string;
    email: string;
    role: "ADMIN" | "EMPLOYEE";
}

export async function signToken(payload: SessionPayload): Promise<string> {
    const token = await new SignJWT(payload)
        .setProtectedHeader({ alg: "HS256" })
        .setIssuedAt()
        .setExpirationTime("1h")
        .sign(new TextEncoder().encode(process.env.JWT_SECRET!));
    return token;
}

export async function verifyToken(token: string): Promise<SessionPayload | null> {
    try {
        const { payload } = await jwtVerify(token, new TextEncoder().encode(process.env.JWT_SECRET!));
        return payload as SessionPayload;
    } catch (error) {
        return null;
    }
}