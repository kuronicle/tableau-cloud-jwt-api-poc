import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';
import { v4 as uuidv4 } from 'uuid';

const auth0Domain = process.env.AUTH0_DOMAIN;
const auth0ClientId = process.env.AUTH0_CLIENT_ID;
const auth0JwksUri = 'https://' + auth0Domain + '/.well-known/jwks.json';
const auth0TokenIssuer = 'https://' + auth0Domain + '/';

const tableauClientId = process.env.TABLEAU_CONNECTED_APP_CLIENT_ID;
const tableauSecretId = process.env.TABLEAU_CONNECTED_APP_SECRET_ID;
const tableauSecretValue = process.env.TABLEAU_CONNECTED_APP_SECRET_VALUE;
const tokenExpiryInMinutes = 10; // max 10 minutes

export const handler = async (event) => {
    console.log({ event });

    const auth0IdToken = event.queryStringParameters.token;

    var verifiedToken;
    try {
         verifiedToken = await verifyToken(auth0IdToken, auth0ClientId, auth0TokenIssuer);
    } catch (error) {
        console.error('Token verification failed:', error);
        return {
            statusCode: 401,
            body: JSON.stringify({ message: 'Unauthorized. Invarid ID token.' }),
        };
    }

    const email = verifiedToken.email;
    if(!email) {
        console.error('Email not found in token:', verifiedToken);
        return {
            statusCode: 401,
            body: JSON.stringify({ message: 'Unauthorized. Email not found in ID token.' }),
        };
    }

    const tableauToken = generateTableauConnectedAppToken(email);

    const response = {
        statusCode: 200,
        body: JSON.stringify({ 
            email: email,
            tableauToken: tableauToken 
        }),
    };
    return response;
};

async function verifyToken(token, audience, issure) {
    try {
        // IDトークンをデコードする
        const decodedToken = jwt.decode(token, { complete: true });
        console.log({ decodedToken });
        if (!decodedToken || typeof decodedToken === 'string') {
            throw new Error('JWTのデコードに失敗しました。decodedToken=' + decodedToken);
        }

        // Auth0の公開鍵を取得する
        const client = jwksClient({ jwksUri: auth0JwksUri });
        const key = await client.getSigningKey(decodedToken.header.kid);
        const publicKey = key.getPublicKey();
        console.log({ publicKey });

        // IDトークンの署名を検証する
        const verifiedToken = jwt.verify(token, publicKey, {
            audience: audience,
            issure,
        });
        console.log({ verifiedToken });

        return verifiedToken;
    } catch (e) {
        if (e instanceof jwt.JsonWebTokenError) {
            console.log('不正なトークンです。token=' + token);
        } else if (e instanceof jwt.TokenExpiredError) {
            console.log('トークンの有効期限が切れています。token=' + token);
        }
        throw e;
    }
};

function generateTableauConnectedAppToken(userId) {
    const scopes = ["tableau:views:embed", "tableau:views:embed_authoring", "tableau:insights:embed"];

    const header = {
        alg: "HS256",
        typ: "JWT",
        kid: tableauSecretId,
        iss: tableauClientId,
    };

    const data = {
        jti: uuidv4(),
        aud: "tableau",
        sub: userId,
        scp: scopes,
        exp: Math.floor(Date.now() / 1000) + tokenExpiryInMinutes * 60
    };

    const token = jwt.sign(data, tableauSecretValue, { header });
    console.log({ token });
    return token;
}