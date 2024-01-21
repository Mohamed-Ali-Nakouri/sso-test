const express = require('express');
const passport = require('passport');
const SamlStrategy = require('passport-saml').Strategy;
const session = require('express-session');
const fs = require('fs');
const path = require('path');
const xml2js = require('xml2js');

const app = express();

// Express middleware setup
app.use(session({ secret: 'your-secret-key', resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

const metadataFilePath = path.join(__dirname, 'sso/metadata/metadata.xml');
const metadataContent = fs.readFileSync(metadataFilePath, 'utf-8');

// Read the certificate from a file
const certFilePath = path.join(__dirname, 'sso/certs/idp/cert');
const certContent = fs.readFileSync(certFilePath);


let samlConfig;

// Parse the SAML metadata XML content
xml2js.parseString(metadataContent, (err, result) => {
    if (err) {

        console.error('Error parsing SAML metadata:', err);
        process.exit(1);
    }

    const entityDescriptor = result['md:EntityDescriptor'];
    const idpDescriptor = entityDescriptor['md:IDPSSODescriptor'];

    //process.exit(1);
    samlConfig = {
        entryPoint: idpDescriptor[0]['md:SingleSignOnService'][0]['$']['Location'],
        issuer: entityDescriptor['$']['entityID'],
        callbackUrl: 'http://localhost:3000/login/callback',
        cert: certContent
    };
    console.log(samlConfig )
    // Passport SAML strategy setup
    passport.use(new SamlStrategy(samlConfig, (profile, done) => {
        return done(null, profile);
    }));
});

passport.serializeUser((user, done) => {
    done(null, user);
});

passport.deserializeUser((user, done) => {
    done(null, user);
});

// Routes
app.get('/', (req, res) => {
    res.send('Home Page');
});

app.get('/login',
    passport.authenticate('saml', { failureRedirect: '/', failureFlash: true }),
    (req, res) => {
        res.redirect('/');
    }
);

app.post('/login/callback',
    passport.authenticate('saml', { failureRedirect: '/', failureFlash: true }),
    (req, res) => {
        // If relay state is provided, redirect to the specified location
        const relayState = req.body.RelayState || '/';
        res.redirect(relayState);
    }
);

app.get('/logout', (req, res) => {
    req.logout();
    res.redirect('/');
});

// Middleware to protect routes
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
}

app.get('/profile', ensureAuthenticated, (req, res) => {
    res.send(`Hello, ${req.user.displayName}!`);
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
