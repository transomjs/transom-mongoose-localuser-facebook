'use strict';
const debug = require('debug')('transom:facebook');
const FacebookLoginHandler = require('./lib/FacebookLoginHandler');
const restifyErrors = require('restify-errors');

function TransomLocalUserFacebook() {
  this.initialize = function(server, options) {
    options = options || {};
	const strategyName = options.strategy || 'facebook';
	
    debug(`Initializing TransomLocalUserFacebook strategy: ${strategyName}`);

    const facebookDefn = server.registry.get(
      'transom-config.definition.facebook',
      {}
    );
    const facebookOptions = Object.assign({}, options, facebookDefn);

	console.log('TransomLocalUserFacebook facebookOptions:', facebookOptions);

    const baseUiUri = facebookOptions.baseUiUri || '<baseUiUri is not set!>';
    const baseApiUri = facebookOptions.baseApiUri || '<baseApiUri is not set!>';
    debug(
      `facebook.baseUiUri = ${baseUiUri}, facebook.baseApiUri = ${baseApiUri}`
    );

    const fbHandler = new FacebookLoginHandler(server, facebookOptions);
    const strategy = fbHandler.createStrategy();

    const passport = server.registry.get('passport');
    passport.use(strategyName, strategy);

    const uriPrefix = server.registry.get(
      'transom-config.definition.uri.prefix'
    );
    const fbConfig = {
      session: false,
      callbackURL: `${baseApiUri}${uriPrefix}/user/${strategyName}-callback`,
      failureMessage: 'Failed',
      successMessage: 'Success',
      scope: 'email'
    };

	// *********************************************************
    server.get(`${uriPrefix}/user/${strategyName}-verify`, function(
      req,
      res,
      next
    ) {
      const nonceToken = req.params['nonce'];
      const transomNonce = server.registry.get('transomNonce');
      transomNonce
        .verifyNonce(nonceToken, (err, bearer) => {
			if (err) {
				return next(err);
			}
			res.json({ bearer });
			next();
		  });
    });

    // *********************************************************
    server.get(`${uriPrefix}/user/${strategyName}-callback`, function(
      req,
      res,
      next
    ) {
      new Promise((resolve, reject) => {
        passport.authenticate(strategyName, fbConfig)(req, res, function(err) {
          if (err) {
            console.log(`Error in ${strategyName}-callback!`, err);
            return reject(new restifyErrors.InternalError(err));
          }
          if (res.req.session && res.req.session.messages) {
            const msg = res.req.session.messages[0];
            let token;
            if (
              res.req.user &&
              res.req.user.bearer &&
              res.req.user.bearer.length
            ) {
              // Since we ALWAYS add new tokens to the end, use the last on in the array.
              token = res.req.user.bearer[res.req.user.bearer.length - 1].token;
            }
            if (msg === fbConfig.successMessage && token) {
              //** Put the token somewhere we can fetch it later!
              const expireSeconds = 30;
              const transomNonce = server.registry.get('transomNonce');
              transomNonce.createNonce(token, expireSeconds, (err, nonce) => {
                if (err) {
                  return reject(new restifyErrors.InternalError(err));
                }
                let successRedirect = facebookOptions.successRedirect || baseUiUri;
                successRedirect +=
                  (successRedirect.indexOf('?') === -1 ? '?' : '&') +
                  `${strategyName}-nonce=${nonce.token}`;

				  console.log({ successRedirect, nonce, token });

                // Send autenticated users back to the UI!
                return resolve(successRedirect);
              });
            } else {
              return reject(
                new restifyErrors.InvalidCredentialsError(
                  'Incorrect or expired Credentials'
                )
              );
            }
          } else {
            return reject(new restify.InvalidCredentialsError('Login failed'));
          }
        });
      })
        .then(redirectUrl => {
          res.redirect(redirectUrl, next);
        })
        .catch(err => {
          console.log(err);
          next(err);
        });
    });

    // *********************************************************
    server.get(`${uriPrefix}/user/${strategyName}`, (req, res, next) => {
      function strategyCallback(err, user, info) {
        if (err) {
          return new restifyErrors.InternalError(err);
        }
        if (!user) {
          return new restifyErrors.InvalidCredentialsError(info);
        }
        return user;
      }
      passport.authenticate(strategyName, fbConfig, strategyCallback)(req, res, next);
    });
  };
}
module.exports = new TransomLocalUserFacebook();
