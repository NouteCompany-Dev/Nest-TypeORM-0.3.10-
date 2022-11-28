import { ExecutionContext, ForbiddenException, Injectable, Logger } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class AccessTokenGuard extends AuthGuard('jwt') {
    // handleRequest(err: any, user: any) {
    //     // You can throw an exception based on either "info" or "err" arguments
    //     if (err || !user) {
    //         throw new UnauthorizedException({
    //             status: 403,
    //             data: { resultCode: -30, data: null },
    //         });
    //     } else {
    //         return user;
    //     }
    // }

    handleRequest<TUser = any>(
        err: any,
        user: any,
        info: any,
        context: ExecutionContext,
        status?: any,
    ): TUser | any {
        // * 엑세스 토큰 확인
        console.log(user);
        // console.log('request >>>', context.switchToHttp().getRequest());
        const accessToken = context.switchToHttp().getRequest().headers['user-auth'];
        const key = process.env.JWT_SECERET;
        console.log('현재 토큰 >>', accessToken);

        // * 토큰 만료여부 확인
        jwt.verify(accessToken.toString(), key, (err: any, userId: any) => {
            if (err) {
                Logger.log('GUARDS - ACCESS_TOKEN_EXPIRED');
                console.log(err);
                throw new ForbiddenException({ resultCode: -30, data: null });
            } else {
                console.log('SUCCESS');
                return super.handleRequest(err, userId, info, context, status);
            }
        });
    }
}
