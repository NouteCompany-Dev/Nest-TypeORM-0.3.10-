import { Request, Response } from 'express';
import { Body, Controller, Logger, Post, Req, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { EmailLoginDto, RenewTokenReqDto } from './dto/auth.dto';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) {}

    @Post('signIn')
    async signIn(@Body() body: EmailLoginDto) {
        return await this.authService.signInByEmail(body);
    }

    @Post('renew')
    async renewToken(@Body() body: RenewTokenReqDto, @Res() res: Response) {
        Logger.log('API - Master Renew Token');
        try {
            const result = await this.authService.renewToken(body);
            res.status(result.status).json(result.data);
        } catch (err) {
            console.log(err);
            res.status(400).json();
        }
    }
}
