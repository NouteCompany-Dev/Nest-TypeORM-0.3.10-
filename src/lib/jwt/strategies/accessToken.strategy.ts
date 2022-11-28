import { Request } from 'express';
import { Injectable, Logger } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { AuthService } from 'src/modules/auth/auth.service';

type JwtPayload = {
    id: number;
};

@Injectable()
export class AccessTokenStrategy extends PassportStrategy(Strategy, 'jwt') {
    constructor(private readonly authService: AuthService) {
        super({
            jwtFromRequest: ExtractJwt.fromHeader('user-auth'),
            secretOrKey: process.env.JWT_SECERET,
            ignoreExpiration: false,
            passReqToCallback: true, // * request를 넘겨주도록
        });
    }

    async validate(req: Request, payload: any, err: any): Promise<any> {
        // console.log('Validate IN JWTStrategy');
        // console.log('================================');
        // console.log('token >>', req.headers['master-auth']);
        // console.log(payload);
        const { userId } = payload;
        const user = await this.authService.checkUser(userId);
        console.log(user);
        if (!user) {
            Logger.log('Not Existed User');
            return { resultCode: -1200, data: null };
        }
        req.user = user;

        return user;
    }
}
