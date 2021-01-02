import jwt from "jsonwebtoken";

import {
    ERROR_COGNITO_AUTH_TOKEN_HEADER_NO_KID,
    ERROR_COGNITO_AUTH_TOKEN_IS_INVALID,
    ERROR_COGNITO_AUTH_TOKEN_KID_NOT_MATCHING,
    ERROR_COGNITO_CLAIM_INVALID_OR_EXPIRED,
    ERROR_COGNITO_CLAIM_ISSUER_INVALID,
    ERROR_COGNITO_CLAIM_USE_IS_NOT_ACCESS,
} from "./cognito.errors";
import {
    ClaimVerifyResult,
    CognitoClaim,
    CognitoPoolInfo,
    CognitoPublicKeyWithPem,
    CognitoTokenHeader,
} from "./cognito.types";

export async function cognitoClaimVerify(
    token: string,
    poolInfo: CognitoPoolInfo,
    cognitoPublicKeys: CognitoPublicKeyWithPem[]
): Promise<ClaimVerifyResult> {
    try {
        const kid = getKidFromToken(token);
        const key = getKeyByKid(cognitoPublicKeys, kid);
        const claim = await getClaimFromToken(token, key.pem);
        validateClaim(claim, poolInfo);

        return {
            userName: claim.username,
            userGuid: claim.sub,
            clientId: claim.client_id,
            isValid: true,
        };
    } catch (e) {
        return {
            isValid: false,
            error: e,
        };
    }
}

function getKidFromToken(token: string): string {
    const tokenSections = (token || "").split(".");

    if (tokenSections.length !== 3) {
        throw ERROR_COGNITO_AUTH_TOKEN_IS_INVALID;
    }

    const header: CognitoTokenHeader = JSON.parse(Buffer.from(tokenSections[0], "base64").toString("utf8"));

    if (!header.kid) {
        throw ERROR_COGNITO_AUTH_TOKEN_HEADER_NO_KID;
    }

    return header.kid;
}

function getKeyByKid(cognitoPublicKeys: CognitoPublicKeyWithPem[], kid: string): CognitoPublicKeyWithPem {
    const publicKey = cognitoPublicKeys.find(e => e.kid === kid);

    if (!publicKey) {
        throw ERROR_COGNITO_AUTH_TOKEN_KID_NOT_MATCHING;
    }

    return publicKey;
}

function getClaimFromToken(token: string, pem: string): Promise<CognitoClaim> {
    return new Promise((resolve, reject) => {
        jwt.verify(token, pem, { algorithms: ["RS256"] }, (error, decodedToken: CognitoClaim) => {
            if (error) {
                reject(error);
            } else {
                resolve(decodedToken);
            }
        });
    });
}

function validateClaim(claim: CognitoClaim, poolInfo: CognitoPoolInfo) {
    const currentSeconds = Math.floor(new Date().valueOf() / 1000);
    if (currentSeconds > claim.exp || currentSeconds < claim.auth_time) {
        throw ERROR_COGNITO_CLAIM_INVALID_OR_EXPIRED;
    }
    if (claim.iss !== `https://cognito-idp.${poolInfo.region}.amazonaws.com/${poolInfo.poolId}`) {
        throw ERROR_COGNITO_CLAIM_ISSUER_INVALID;
    }
    if (claim.token_use !== "access") {
        throw ERROR_COGNITO_CLAIM_USE_IS_NOT_ACCESS;
    }
}
