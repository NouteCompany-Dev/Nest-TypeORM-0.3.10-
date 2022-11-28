import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';

export const GetUser = createParamDecorator((data: unknown, ctx: ExecutionContext): any => {
    const request = ctx.switchToHttp().getRequest();
    const accessToken = request.headers['user-auth'];
    const key = process.env.JWT_SECERET;
    const payload = jwt.verify(accessToken.toString(), key);
    return payload;
});
