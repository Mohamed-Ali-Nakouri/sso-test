const express = require('express');
const passport = require('passport');
const SamlStrategy = require('passport-saml').Strategy;
const fs = require('fs');
const xml2js = require('xml2js');
const {join, resolve} = require("path");

const app = express();

// Read the certificate from a file
const certFilePath = join(__dirname, 'sso/certs/idp/cert');
const certContent = fs.readFileSync(certFilePath);
// Function to read and parse metadata from a file
function parseMetadata(metadataFilePath) {
    const metadataContent = fs.readFileSync(metadataFilePath, 'utf-8');
    return new Promise((resolve, reject) => {
        xml2js.parseString(metadataContent, { explicitArray: false }, (err, result) => {
            if (err) {
                reject(err);
            } else {
                resolve(result);
            }
        });
    });
}
let idpSamlConfig = null;
// Read and parse IdP metadata
const idpMetadataFilePath = 'sso/metadata/idp-metadata.xml'; // Replace with the actual path
parseMetadata(idpMetadataFilePath)
    .then((idpMetadata) => {
        const idpEntryPoints = idpMetadata['md:EntityDescriptor']['md:IDPSSODescriptor']['md:SingleSignOnService'];
        const idpSsoUrl = Array.isArray(idpEntryPoints) ? idpEntryPoints[0]['$']['Location'] : idpEntryPoints['$']['Location'];
        console.log('before config')
        // Identity Provider (IdP) Configuration
         idpSamlConfig = {
            path: 'http://localhost:3000/login/callback',
            entryPoint: idpSsoUrl,
            issuer: idpMetadata['md:EntityDescriptor']['$']['entityID'],
            cert: certContent.toString('utf-8'), // Include if IdP provides a signing certificate
            authnRequestBinding:"HTTP-POST",
            // samlOptions: {
            //      attributes: {
            //          'firstName': 'John', // First Name
            //          'lastName': 'Doe',  // Last Name
            //          'email': 'john.doe@example.com', // Email
            //          'eppn': 'john.doe', // ePPN (eduPersonPrincipalName)
            //      },
            //  },
        };
        console.log(idpSamlConfig)
        passport.use("saml",new SamlStrategy(idpSamlConfig, (profile, done) => {
            console.log('reached here')
            try {
                console.log('Authentication Successful. Profile:', profile);
                // Handle user authentication and authorization for the IdP here
                return done(null, profile);
            } catch (error) {
                console.error('Authentication Error:', error);
                return done(error, false);
            }
            // Handle user authentication and authorization for the IdP here

        }));
        console.log('test log')

    })
    .catch((err) => {
        console.error('Error parsing IdP metadata:', err);
        process.exit(1);
    });





// Read and parse SP metadata
// const spMetadataFilePath = 'sso/metadata/coursera-sp-metadata.xml'; // Replace with the actual path
// parseMetadata(spMetadataFilePath)
//     .then((spMetadata) => {
//         console.log(spMetadata['EntityDescriptor']["$"]['entityID'])
//         process.exit(1)
//         const spEntryPoints = spMetadata['EntityDescriptor']['SPSSODescriptor']['md:AssertionConsumerService'];
//         const spAcsUrl = Array.isArray(spEntryPoints) ? spEntryPoints[0]['$']['Location'] : spEntryPoints['$']['Location'];
//
//         // Service Provider (SP) Configuration
//         const spSamlConfig = {
//             callbackUrl: 'https://your-app.example.com/sso/callback',
//             entryPoint: spAcsUrl,
//             issuer: spMetadata['EntityDescriptor']['$']['entityID'],
//             cert: certContent.toString('utf-8'), // Include your SP's certificate
//         };
//
//         passport.use('sp', new SamlStrategy(spSamlConfig, (profile, done) => {
//             // Handle user authentication and authorization for the SP here
//             return done(null, profile);
//         }));
//     })
//     .catch((err) => {
//         console.error('Error parsing SP metadata:', err);
//         process.exit(1);
//     });

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

app.get(
    "/login",
    passport.authenticate("saml", { failureRedirect: "/", failureFlash: true }),
    function (req, res) {
        res.redirect("/");
    }
);

app.post('/login/callback', (req, res, next) => {
    console.log('Incoming POST Request to /login/callback:', req.body, req.headers);
    passport.authenticate('saml', (err, user, info) => {
        if (err) { return next(err); }
        if (!user) { return res.status(401).send(info); }

        // Log the entire SAML response
        console.log('SAML Response:', user);

        // If relay state is provided, redirect to the specified location
        const relayState = req.body.RelayState || '/';
        res.redirect(relayState);
    })(req, res, next);
});

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
