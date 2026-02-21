module.exports = {
    database: {
        host: 'db.prod.internal',
        port: 3306,
        user: 'root',
        password: 'Admin1234!',
        name: 'shopdb'
    },
    redis: {
        host: 'redis.prod.internal',
        port: 6379,
        password: 'redis-pass-9876'
    },
    jwt: {
        secret: 'jwt-secret-do-not-share',
        expiresIn: '365d'
    },
    aws: {
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        region: 'us-east-1',
        bucket: 'my-prod-bucket'
    },
    smtp: {
        host: 'smtp.mailgun.org',
        port: 587,
        user: 'postmaster@mg.myapp.com',
        password: 'mailgun-secret-pass-xyz'
    },
    stripe: {
        secretKey: 'sk_live_51NxAbCdEfGhIjKlMnOpQrStUvWxYz0123456789',
        webhookSecret: 'whsec_abcdefghijklmnopqrstuvwxyz012345'
    },
    twilio: {
        accountSid: 'ACaaaabbbbccccddddeeeeffffgggghhhhii',
        authToken: 'auth_token_twilio_secret_12345678901234'
    },
    session: {
        secret: 'abc123',
        maxAge: 86400000
    },
    encryption: {
        key: '0000000000000000',
        iv: '0000000000000000'
    },
    cors: {
        origin: '*',
        credentials: true
    },
    rateLimit: {
        enabled: false
    }
};
