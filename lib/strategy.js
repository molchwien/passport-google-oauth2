// Load modules.
var OAuth2Strategy = require('passport-oauth2')
  , util = require('util')
  , uri = require('url')
  , InternalOAuthError = require('passport-oauth2').InternalOAuthError
  , MolchAPIError = require('./errors/molchapierror')
  , UserInfoError = require('./errors/userinfoerror');


/**
 * `Strategy` constructor.
 *
 * The Molch authentication strategy authenticates requests by delegating to
 * Molch using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `cb`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Molch application's client id
 *   - `clientSecret`  your Molch application's client secret
 *   - `callbackURL`   URL to which Molch will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new MolchStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/molch/callback'
 *       },
 *       function(accessToken, refreshToken, profile, cb) {
 *         User.findOrCreate(..., function (err, user) {
 *           cb(err, user);
 *         });
 *       }
 *     ));
 *
 * @constructor
 * @param {object} options
 * @param {function} verify
 * @access public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://auth.molch.at/oauth2/authorize';
  options.tokenURL = options.tokenURL || 'https://auth.molch.at/oauth2/token/index.pl';

  OAuth2Strategy.call(this, options, verify);
  this.name = 'molch';
  this._userProfileURL = options.userProfileURL || 'https://auth.molch.at/oauth2/userinfo/index.pl';
  
  var url = uri.parse(this._userProfileURL);
  if (url.pathname.indexOf('/userinfo') == (url.pathname.length - '/userinfo'.length)) {
    this._userProfileFormat = 'openid';
  } else {
    this._userProfileFormat = 'molch'; // Molch Sign-In
  }
}

// Inherit from `OAuth2Strategy`.
util.inherits(Strategy, OAuth2Strategy);


/**
 * Retrieve user profile from Molch.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `molch`
 *   - `id`
 *   - `username`
 *   - `displayName`
 *
 * @param {string} accessToken
 * @param {function} done
 * @access protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  var self = this;
  this._oauth2.get(this._userProfileURL, accessToken, function (err, body, res) {
    var json;
    
    if (err) {
      if (err.data) {
        try {
          json = JSON.parse(err.data);
        } catch (_) {}
      }
      
      if (json && json.error && json.error.message) {
        return done(new MolchPlusAPIError(json.error.message, json.error.code));
      } else if (json && json.error && json.error_description) {
        return done(new UserInfoError(json.error_description, json.error));
      }
      return done(new InternalOAuthError('Failed to fetch user profile', err));
    }
    
    try {
      json = JSON.parse(body);
    } catch (ex) {
      return done(new Error('Failed to parse user profile'));
    }
    
    var profile;
    switch (self._userProfileFormat) {
    case 'openid':
      profile = OpenIDProfile.parse(json);
      break;
    default: // Molch Sign-In
      profile = MolchPlusProfile.parse(json);
      break;
    }
    
    profile.provider  = 'molch';
    profile._raw = body;
    profile._json = json;
    
    done(null, profile);
  });
}

/**
 * Return extra Molch-specific parameters to be included in the authorization
 * request.
 *
 * @param {object} options
 * @return {object}
 * @access protected
 */
Strategy.prototype.authorizationParams = function(options) {
  var params = {};
  
  if (options.accessType) {
    params['access_type'] = options.accessType;
  }
  if (options.prompt) {
    params['prompt'] = options.prompt;
  }
  if (options.loginHint) {
    params['login_hint'] = options.loginHint;
  }
  if (options.includeGrantedScopes) {
    params['include_granted_scopes'] = true;
  }
  
  if (options.display) {
    params['display'] = options.display;
  }
  
  
  // OpenID 2.0 migration
  if (options.openIDRealm) {
    // This parameter is needed when migrating users from Molch's OpenID 2.0 to OAuth 2.0
    //   https://developers.molch.com/accounts/docs/OpenID?hl=ja#adjust-uri
    params['openid.realm'] = options.openIDRealm;
  }
  
  // Undocumented
  if (options.approvalPrompt) {
    params['approval_prompt'] = options.approvalPrompt;
  }
  if (options.userID) {
    // Undocumented, but supported by Molch's OAuth 2.0 endpoint.  Appears to
    // be equivalent to `login_hint`.
    params['user_id'] = options.userID;
  }
  
  return params;
}


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
