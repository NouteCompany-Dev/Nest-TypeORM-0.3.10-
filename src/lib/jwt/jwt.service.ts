import { Injectable } from '@nestjs/common';
import jwt from 'jsonwebtoken';
import { generateRandomString } from 'src/utils/generateRandom';

@Injectable()
export class JwtService {
    private readonly jwtSecret: string;
    constructor() {
        this.jwtSecret = process.env.JWT_SECERET;
    }

    getToken(userId: number) {
        const randomString = generateRandomString();
        const accessToken: string = jwt.sign({ userId: userId }, this.jwtSecret, { expiresIn: '12h' });
        const refreshToken: string = jwt.sign({ randomString }, this.jwtSecret, { expiresIn: '7d' });
        return { accessToken, refreshToken };
    }

    getRenewToken = (userId) => {
        const accessToken = jwt.sign({ userId }, this.jwtSecret, { expiresIn: '12h' });
        return { accessToken };
    };
}
