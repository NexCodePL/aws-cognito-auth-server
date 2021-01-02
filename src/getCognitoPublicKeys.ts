import { get } from "https";
import jwkToPem from "jwk-to-pem";
import { ERROR_COGNITO_PUBLIC_KEY_KTY_NOT_RSA } from "./cognito.errors";

import { CognitoPoolInfo, CognitoPublicKey, CognitoPublicKeyWithPem } from "./cognito.types";

function loadCognitoPublicKeys(poolInfo: CognitoPoolInfo): Promise<{ keys: CognitoPublicKey[] }> {
    return new Promise((resolve, reject) => {
        const body: Buffer[] = [];
        get(
            `https://cognito-idp.${poolInfo.region}.amazonaws.com/${poolInfo.poolId}/.well-known/jwks.json`,
            response => {
                response.on("data", (chunk: Buffer) => {
                    body.push(chunk);
                });

                response.on("end", () => {
                    const data = Buffer.concat(body).toString();

                    try {
                        const parsedData = JSON.parse(data);
                        if (response.statusCode === 200) {
                            resolve(parsedData);
                        } else {
                            reject({
                                code: response.statusCode,
                                data: parsedData,
                            });
                        }
                    } catch (e) {
                        reject(e);
                    }
                });

                response.on("error", error => {
                    reject(error);
                });
            }
        );
    });
}

export async function getCognitoPublicKeys(poolInfo: CognitoPoolInfo): Promise<CognitoPublicKeyWithPem[]> {
    const { keys } = await loadCognitoPublicKeys(poolInfo);
    return keys.map(key => {
        if (key.kty !== "RSA") {
            throw ERROR_COGNITO_PUBLIC_KEY_KTY_NOT_RSA;
        }
        return {
            ...key,
            pem: jwkToPem(key),
        };
    });
}
