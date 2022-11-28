import { Request } from 'express';
import { User } from '../../models/User.entity';
import { GenDigestPwd } from '../../utils/crypto';
import { UserRepository } from '../../repositories/user.repository';
import { Injectable, Logger } from '@nestjs/common';
import { EmailLoginDto, RenewTokenReqDto } from './dto/auth.dto';
import { JwtService } from 'src/lib/jwt/jwt.service';
import { AccountStatus } from 'src/models/enum/enum';
import jwt from 'jsonwebtoken';

@Injectable()
export class AuthService {
    constructor(private userRepository: UserRepository, private readonly jwtService: JwtService) {}

    async checkUser(userId: number) {
        let user = null;
        try {
            user = await this.userRepository.findById(userId);
        } catch (err) {
            console.log(err);
        }

        return user;
    }

    async signInByEmail(body: EmailLoginDto): Promise<any> {
        try {
            const { email, password } = body;
            //Check if user exist
            const user: User = await this.userRepository.findByEmail(email);
            let status = 0;
            let resultCode = 0;
            let data: any = null;
            if (user) {
                if (user.accountStatus === AccountStatus.enable) {
                    const hashPassword = GenDigestPwd(password);
                    if (user.password === hashPassword) {
                        data = this.jwtService.getToken(user.id);
                        user.lastLoginAt = new Date();
                        this.userRepository.save(user);
                        status = 200;
                        resultCode = 1;
                    } else {
                        status = 202;
                        resultCode = 1002; //비밀번호 틀림
                    }
                } else {
                    status = 201;
                    resultCode = 1001; // 탈퇴한 회원
                }
            } else {
                status = 203;
                resultCode = 1003; //계정 없음
            }
            return { status: status, data: { resultCode: resultCode, data: data } };
        } catch (err) {
            console.log(err);
            return { status: 401, data: { resultCode: 1005, data: null } };
        }
    }

    async renewToken(body: RenewTokenReqDto): Promise<any> {
        try {
            let status = 0;
            let data = null;
            let resultCode = 0;
            const { accessToken, refreshToken } = body;
            const jwtSecret = process.env.JWT_SECERET;
            jwt.verify(refreshToken, jwtSecret, (err: any, randomString: any) => {
                const userId = jwt.verify(accessToken, jwtSecret);
                if (err) {
                    Logger.log('API - REFRESHTOKEN_EXPIRED');
                    status = 200;
                    resultCode = 9006;
                } else if (userId) {
                    Logger.log('API - RENEW ACCESSTOKEN');
                    const accessToken = this.jwtService.getRenewToken(userId);
                    status = 200;
                    resultCode = 1;
                    data = accessToken;
                }
            });

            console.log('new Token >> ', data);
            return { status, data: { resultCode, data } };
        } catch (err) {
            console.log(err);
            return { status: 401, data: { resultCode: 9005, data: null } };
        }
    }
}
