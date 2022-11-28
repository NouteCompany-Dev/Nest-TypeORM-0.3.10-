import { ApiProperty } from '@nestjs/swagger';

export class EmailLoginDto {
    @ApiProperty()
    email: string;

    @ApiProperty()
    password: string;
}

export class RenewTokenReqDto {
    accessToken: string;
    refreshToken: string;
}
