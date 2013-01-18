/*
 * expressive-auth
 * https://github.com/Aomitayo/expressive-auth
 *
 * Copyright (c) 2012 Adedayo Omitayo
 * Licensed under the MIT license.
 *
 * Expressive auth depends on a User object that supports specific properties and methods. These include:
 * Properties
 *     isNew
 *     id
 *     active
 * Instance Methods
 *     toObject
 *     addAccount
 *     setCredential(credentials)
 *     save
 * Static methods
 *     findById
 *     findByAccount
 *     findByCredentials
 */
var debug = require('debug')('expressive-auth');

var passport = require('passport');

function proxy(context, fn){
    return function(){
        var args = Array.prototype.slice.call(arguments, 0);
        fn.apply(context, args);
    };
}

function ExpressiveAuth(app, authConfig, User){
    var self = this;

    self.authConfig = {
        strategyKeyParam : "strategyKey",
        authorizationRoutePattern : '/account/authorize/:strategyKey',
        authenticationCallbackRoutePattern : '/account/authenticate/:strategyKey/callback',
        authorizationCallbackRoutePattern : '/account/authorize/:strategyKey/callback',
        authenticationRoutePattern : '/account/authenticate/:strategyKey',
        callbackRoutePattern : '/account/authenticate/:strategyKey/callback',
        authSuccessRoute : '/',
        authFailureRoute : '/account/auth',
        logoutRoute : '/account/logout',
        logoutRedirectRoute : '/',
        registrationRoute: '/account/register'
    };
    
    Object.keys(authConfig).forEach(function(k){
        self.authConfig[k] = authConfig[k];
    });

    self.passport = passport;
    self.passport.serializeUser(proxy(self, self.serializeUserToSession));
    self.passport.deserializeUser(proxy(self, self.deserializeUserFromSession));

    self.User = User || require('User');

    app.use(self.middleware());

    self.putExpressRoutes(app, self.authConfig);
}

ExpressiveAuth.prototype.middleware = function(){
    var self = this;
    var passportInitialize = self.passport.initialize();
    var passportSession = self.passport.session();

    return function ExpressiveAuthMiddleware(req, res, next){
        debug('security middleware');
        passportInitialize(req, res, function(err){
            debug('Passport initialize');
            if(err){return next(err);}
            return passportSession(req, res, next);
        });
    };
};

ExpressiveAuth.prototype.serializeUserToSession = function(user, done) {
    debug('Serializing User: ', user);

    if(user.isNew){
        done(null, user.toObject());
    }
    else{
        done(null, user.id);
    }
};

ExpressiveAuth.prototype.deserializeUserFromSession = function(data, done) {
    debug('Deserializing User from: ', data);

    var self = this;
    if(typeof data == 'string'){
        self.User.findById(data, function (err, user) {
            done(err, user);
        });
    }
    else{
        user = new self.User(data);
        done(null, user);
    }
};

ExpressiveAuth.prototype.getStrategyInfo = function(strategyKey){
    var self = this;
    var info = {
        'local': {
            packageName: 'passport-local',
            factoryKey: 'Strategy',
            verifyCallback: proxy(self, self.localVerifyCallback)
        },
        'google':{
            packageName: 'passport-google-oauth',
            factoryKey: 'OAuth2Strategy',
            verifyCallback: proxy(self, self.OAUTH2VerifyCallback)
        },
        'facebook':{
            packageName: 'passport-facebook',
            factoryKey: 'Strategy',
            verifyCallback: proxy(self, self.OAUTH2VerifyCallback)
        },
        'twitter': {
            packageName: 'passport-twitter',
            factoryKey: 'Strategy',
            verifyCallback: proxy(self, self.OAUTH2VerifyCallback)
        }
    };
    return info[strategyKey];
};

ExpressiveAuth.prototype.initPassportStrategies = function(strategyKey, strategyOptions, callbackURL){
    var self = this;
    if(self.passport._strategy(strategyKey)){return;}
    strategyOptions = strategyOptions || {};
    var strategyInfo = this.getStrategyInfo(strategyKey);
    if(!strategyInfo){throw new Error('Unsupported Strategy');}
    var strategyConfig = {
        callbackURL: callbackURL
    };

    Object.keys(strategyOptions).forEach(function(key){
        strategyConfig[key] = strategyOptions[key];
    });

    var Strategy = require(strategyInfo.packageName)[strategyInfo.factoryKey];

    self.passport.use(strategyKey, new Strategy(strategyConfig, strategyInfo.verifyCallback) );
};

ExpressiveAuth.prototype.logout = function(req, res, next){
    var self = this;
    delete req.session.authorizingUserId;
    req.logout();
    res.redirect(self.authConfig.logoutRedirectRoute);
};

ExpressiveAuth.prototype.beginAuthenticate = function(req, res, next){
    var self = this;
    var strategyKeyParam = self.authConfig.strategyKeyParam;
    var strategyKey = req.params[strategyKeyParam];

    var callbackURL = 'http://'+ req.header('host') + self.authConfig.authenticationCallbackRoutePattern.replace(':' + strategyKeyParam, strategyKey);
    try{
        self.initPassportStrategies(strategyKey, self.authConfig.strategies[strategyKey], callbackURL);
    }
    catch(err){
        console.trace(err);
        return res.send(err.message, 400);
    }

    var authOptions = self.authConfig.strategies[strategyKey]['authenticate'] || {};
    return self.passport.authenticate(strategyKey, authOptions)(req, res, next);
};

ExpressiveAuth.prototype.beginAuthorize = function(req, res, next){
    var self = this;
    var strategyKeyParam = self.authConfig.strategyKeyParam;
    var strategyKey = req.params[strategyKeyParam];

    var callbackURL = 'http://'+ req.header('host') + self.authConfig.authorizationCallbackRoutePattern.replace(':' + strategyKeyParam, strategyKey);
    try{
        self.initPassportStrategies(strategyKey, self.authConfig.strategies[strategyKey], callbackURL);
    }
    catch(err){
        console.trace(err);
        return res.send(err.message, 400);
    }

    var authOptions = self.authConfig.strategies[strategyKey]['authorize'] || {};
    return self.passport.authenticate(strategyKey, authOptions)(req, res, next);
};

ExpressiveAuth.prototype.completeAuthenticate = function(req, res, next){
    var self = this;
    var strategyKeyParam = self.authConfig.strategyKeyParam;
    var strategyKey = req.params[strategyKeyParam];
    var callbackURL = 'http://'+ req.header('host') + self.authConfig.authorizationCallbackRoutePattern.replace(':' + strategyKeyParam, strategyKey);
    try{
        self.initPassportStrategies(strategyKey, self.authConfig.strategies[strategyKey], callbackURL);
    }
    catch(err){
        console.trace(err);
        return res.send(err.message, 400);
    }

    function authFail(statusCode){
        errInstance = new Error();
        errInstance.name = 'HttpError';
        errInstance.statusCode = statusCode;
        return next(errInstance);
    }
    return passport.authorize(strategyKey, function(err, user, info){
        var errorMessage, errInstance;
        if(err){
            errorMessage = err.message || 'User could not be authenticated';
            req.flash('auth_error', errorMessage);
            //return res.redirect(self.authConfig.authFailureRoute);
            return authFail(500);
        }
        else if(!user){
            errorMessage = (info || {}).message || 'User could not be authenticated';
            req.flash('auth_error', errorMessage);
            //return res.redirect(self.authConfig.authFailureRoute);
            return authFail(401);
        }
        else{
            return req.login(user, function(err){
                if(err){
                    //return res.redirect(self.authConfig.authFailureRoute);
                    return authFail(500);
                }
                else{
                    if(!user.active){
                        return res.redirect(self.authConfig.registrationRoute);
                    }
                    else{
                        return res.redirect(self.authConfig.authSuccessRoute);
                    }
                }
            });
        }
        
    })(req, res, next);
};

ExpressiveAuth.prototype.completeAuthorize = function(req, res, next){
    var self = this;
    var strategyKeyParam = self.authConfig.strategyKeyParam;
    var strategyKey = req.params[strategyKeyParam];
    var callbackURL = 'http://'+ req.header('host') + self.authConfig.authorizationCallbackRoutePattern.replace(':' + strategyKeyParam, strategyKey);
    try{
        self.initPassportStrategies(strategyKey, self.authConfig.strategies[strategyKey], callbackURL);
    }
    catch(err){
        console.trace(err);
        return res.send(err.message, 400);
    }

    function authFail(statusCode){
        errInstance = new Error();
        errInstance.name = 'HttpError';
        errInstance.statusCode = statusCode;
        return next(errInstance);
    }
    return passport.authorize(strategyKey, function(err, user, info){
        var errorMessage;
        if(err){
            errorMessage = err.message || 'User could not be authenticated';
            req.flash('auth_error', errorMessage);
            //return res.redirect(self.authConfig.authFailureRoute);
            return authFail(500);
        }
        else if(!user){
            errorMessage = (info || {}).message || 'User could not be authenticated';
            req.flash('auth_error', errorMessage);
            //return res.redirect(self.authConfig.authFailureRoute);
            return authFail(401);
        }
        else{
            return req.login(user, function(err){
                if(err){
                    //return res.redirect(self.authConfig.authFailureRoute);
                    return authFail(500);
                }
                else{
                    if(!user.active){
                        return res.redirect(self.authConfig.registrationRoute);
                    }
                    else{
                        return res.redirect(self.authConfig.authSuccessRoute);
                    }
                }
            });
        }
        
    })(req, res, next);
};

ExpressiveAuth.prototype.putExpressRoutes = function(router, authConfig){
    var self = this;

    router.get(self.authConfig.authorizationRoutePattern, proxy(self, self.beginAuthorize));
    router.get(self.authConfig.authenticationRoutePattern, proxy(self, self.beginAuthenticate));

    router.all(self.authConfig.authorizationCallbackRoutePattern, proxy(self, self.completeAuthorize));
    router.all(self.authConfig.authenticationCallbackRoutePattern, proxy(self, self.completeAuthorize));
    
    router.all(self.authConfig.logoutRoute, proxy(self, self.logout));
};

ExpressiveAuth.prototype.OAUTHVerifyCallback = function(token, tokenSecret, profile, done){};

ExpressiveAuth.prototype.OAUTH2VerifyCallback = function(accessToken, refreshToken, profile, done){
    var self = this;

    if(!profile){
        return done(null, false, {message:'Authentication failed'});
    }

    var credentials = {provider: profile.provider, type:'OAUTH2', accessToken:accessToken, refreshToken:refreshToken};
    
    self.User.findByAccount(profile.provider, profile.id, function(err, user){
        if(err){ return done(err, false);}

        if(!user){
            var provided_profile = {};
            for(var key in profile){
                if(key.charAt(0) != '_'){ provided_profile[key] = profile[key];}
            }
            user = new self.User({
                profile: provided_profile,
                is_confirmed: false
            });
            debug('new profile: ' + JSON.stringify(profile));
            user.addAccount({
                provider: profile.provider,
                username: profile.username,
                userid: profile.id
            });
            user.setOauthCredentials(credentials);

            return done(null, user);
        }
        else{
            debug('Existing profile: ' + JSON.stringify(profile));
            user.addAccount({
                provider: profile.provider,
                username: profile.username,
                userid: profile.id
            });
            user.setCredentials(credentials);
            
            return user.save(function(err, user){
                if(err){return done(err, null,  {message:'User account could not be connected'});}
                else{return done(null, user);}
            });
        }
    });
};

ExpressiveAuth.prototype.localVerifyCallback = function(username, password, done){
    var self = this;
    self.User.findByCredentials({type: 'local', username:username, password:password}, function(err, user){
        if(err){return done(err, null);}

        if(!user){
            return done(null, false, {message:'Incorrect Email or password '});
        }
        return done(null, user);
    });
};

module.exports = ExpressiveAuth;
