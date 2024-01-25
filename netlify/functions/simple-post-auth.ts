import { Handler } from '@netlify/functions';
import * as jose from 'jose';

const jwks = jose.createRemoteJWKSet(new URL('https://extensions-test.criipto.com/service/.well-known/jwks'));

const handler: Handler = async (event, context) => {
  context.callbackWaitsForEmptyEventLoop = false;
  if (event.httpMethod !== 'POST') return {statusCode: 405};

  const authorization = event.headers['Authorization'];
  if (!authorization) return {statusCode: 401, body: JSON.stringify({message: 'no bearer token'})};
  const bearer = authorization.startsWith('Bearer') ? authorization.replace('Bearer ', '') : null;
  if (!bearer) return {statusCode: 401, body: JSON.stringify({message: 'no bearer token'})};

  const payload = await jose.jwtVerify(bearer, jwks, {
    issuer: 'https://extensions-test.criipto.com/service/.well-known/jwks',
    clockTolerance: '5 minutes',
    maxTokenAge: '5 minutes'
  });

  try {

    return {
      statusCode: 200,
      body: JSON.stringify({
        claims: {
          'https://criipto-extensions-webhook-sample.netlify.app/simple-post-auth/string': 'hello-world',
          'https://criipto-extensions-webhook-sample.netlify.app/simple-post-auth/number': 123456,
          'https://criipto-extensions-webhook-sample.netlify.app/simple-post-auth/boolean': true,
          "https://criipto-extensions-webhook-sample.netlify.app/simple-post-auth/array": ["hello-world",123456,true,{"hello":"world"}],
          'https://criipto-extensions-webhook-sample.netlify.app/simple-post-auth/complex': {
            hello: 'world'
          }
        }
      })
    }
  } catch (err) {
    if (err instanceof jose.errors.JWTInvalid) return {statusCode: 401, body: JSON.stringify({message: 'jwt invalid'})};
    if (err instanceof jose.errors.JWSInvalid) return {statusCode: 401, body: JSON.stringify({message: 'jwt invalid'})};
    if (err instanceof jose.errors.JWTExpired) return {statusCode: 401, body: JSON.stringify({message: 'jwt expired'})};
    return {statusCode: 500, body: JSON.stringify({message: err?.toString()})}
  }
}

export { handler };