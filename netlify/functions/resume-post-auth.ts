import { Handler } from '@netlify/functions';
import * as jose from 'jose';

const jwks = jose.createRemoteJWKSet(new URL('https://extensions-test.criipto.com/service/.well-known/jwks'));

const handler: Handler = async (event, context) => {
  context.callbackWaitsForEmptyEventLoop = false;
  if (event.httpMethod !== 'POST') return {statusCode: 405};

  const authorization = event.headers['authorization'];
  if (!authorization) return {statusCode: 401, body: JSON.stringify({message: 'no bearer token'})};
  const bearer = authorization.startsWith('Bearer') ? authorization.replace('Bearer ', '') : null;
  if (!bearer) return {statusCode: 401, body: JSON.stringify({message: 'no bearer token'})};
  try {
    // Ideally validate audience as well, but audience is not known until after install
    const payload = await jose.jwtVerify(bearer, jwks, {
      issuer: ['https://extensions.criipto.com/service', 'https://extensions-test.criipto.com/service', 'https://deploy-preview-64.extensions-test.criipto.com/service'],
      clockTolerance: '5 minutes',
      maxTokenAge: '5 minutes'
    });

    // TODO: add jti validation for replay detection
    const body = JSON.parse(event.body!);

    if (body.event === 'post-auth-event-1.0') {
      return {
        statusCode: 303,
        headers: {
          Location: `https://extensions-by-criipto-webhook-sample.netlify.app/terms?resumeUrl=${encodeURIComponent(body.resumeUrl)}`
        }
      };
    }
    
    if (body.event === 'post-auth-resume-event-1.0') {
      const resumedUrl = new URL(body.resumeRequest.url);
      return {
        statusCode: 200,
        body: JSON.stringify({
          claims: {
            'https://extensions-by-criipto-webhook-sample.netlify.app/terms': resumedUrl.searchParams.has('accepted') ? 'accepted' : 'rejected'
          }
        })
      };
    }

    throw new Error(`Unknown event: ${body.event}`);
  } catch (err) {
    if (err instanceof jose.errors.JWTInvalid) return {statusCode: 401, body: JSON.stringify({message: 'jwt invalid'})};
    if (err instanceof jose.errors.JWSInvalid) return {statusCode: 401, body: JSON.stringify({message: 'jwt invalid'})};
    if (err instanceof jose.errors.JWTExpired) return {statusCode: 401, body: JSON.stringify({message: 'jwt expired'})};
    if (err instanceof jose.errors.JWTClaimValidationFailed) {
      if (err.claim === 'iss') return {statusCode: 401, body: JSON.stringify({message: 'invalid issuer'})};
      return {statusCode: 401, body: JSON.stringify({message: 'jwt expired'})};
    }
    return {statusCode: 500, body: JSON.stringify({message: err?.toString()})}
  }
}

export { handler };