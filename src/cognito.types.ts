export interface CognitoPoolInfo {
    poolId: string;
    clientId: string;
    region: string;
}

export interface CognitoPublicKey {
    alg: string;
    e: string;
    kid: string;
    kty: "RSA";
    n: string;
    use: string;
}

export interface CognitoPublicKeyWithPem extends CognitoPublicKey {
    pem: string;
}

export interface CognitoTokenHeader {
    kid: string;
    alg: string;
}

export interface CognitoClaim {
    token_use: string;
    auth_time: number;
    iss: string;
    exp: number;
    username: string;
    client_id: string;
    sub: string;
}

interface ClaimVerifyResultValid {
    readonly userName: string;
    readonly clientId: string;
    readonly userGuid: string;
    readonly isValid: true;
}

interface ClaimVerifyResultInvalid {
    readonly isValid: false;
    readonly error?: string;
}

export type ClaimVerifyResult = ClaimVerifyResultInvalid | ClaimVerifyResultValid;
