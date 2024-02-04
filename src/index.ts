import express, {Request, Response} from 'express';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import {fileURLToPath} from 'url';
import path, {dirname} from 'path';
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const PORT = 4001;
const SECRET = 'a09353a06dd0b7ea5832c9d57a1ff524b91b7f96048c75e58a5a8cda3aaf1f68';
const MY_ACCESS_TOKEN = 'MY_ACCESS_TOKEN';
const MY_REFRESH_TOKEN = 'MY_REFRESH_TOKEN';
const app = express();

app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(cookieParser());

// Keeps track of refresh tokens belonging to each user
const refreshTokenMap = new Map<string, string[]>();

/**
 * Logging to help separate each request
 */
app.use((req, res, next) => {
  console.log('----------------');
  return next();
});

/**
 * Home page for logging in
 */
app.get('/', (req, res) => {
  const accessToken = req.cookies[MY_ACCESS_TOKEN];
  if (!accessToken) {
    return res.status(200).sendFile(path.resolve(__dirname, '../', 'public', 'index.html'));
  }
  res.redirect('/profile');
});

/**
 * Handle the login payload
 */
app.post('/login', (req, res) => {
  const {username, password} = req.body;
  // Login successful
  if (username === 'WittCode' && password === 'subscribe') {
    // Generate access and refresh tokens
    const accessToken = jwt.sign({username}, SECRET, {expiresIn: '1h'});
    const refreshToken = jwt.sign({username}, SECRET, {expiresIn: '30d'});

    // Keep track of a user's refresh tokens so if they get compromised we can remove them
    const refreshTokens = refreshTokenMap.get(username) ?? [];
    refreshTokens.push(refreshToken);
    refreshTokenMap.set(username, refreshTokens);

    // Create access token cookie
    res.cookie(MY_ACCESS_TOKEN, accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      // 1 hr
      maxAge: 60 * 60 * 1000
    });

    // Create refresh token cookie that is only sent in requests to /refresh
    res.cookie(MY_REFRESH_TOKEN, refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      path: '/refresh',
      // 30 days
      maxAge: 30 * 24 * 60 * 60 * 1000
    });

    // Password and username correct redirect to profile
    console.log('Correct username and password');
    return res.redirect('/profile');
  } else {
    // Wrong password and username
    console.log('Incorrect username and password');
    return res.redirect('/');
  }
});

/**
 * Handle the refresh token. Needs to be before the authentication
 * middleware so we can get a new access token when the refresh token
 * has expired.
 */
app.get('/refresh', (req, res) => {
  console.log('Obtaining new access token with the refresh token');
  // Get the refresh token, will only be present on /refresh call
  const refreshToken = req.cookies[MY_REFRESH_TOKEN];

  // Refresh token is not present
  if (!refreshToken) {
    console.log('Refresh token not found, sending them to login page');
    return res.redirect('/');
  }

  // Create a new access token and set it on the cookie
  try {
    const {username} = jwt.verify(refreshToken, SECRET) as {username: string};
    const accessToken = jwt.sign({username}, SECRET, {expiresIn: '1h'});
    res.cookie(MY_ACCESS_TOKEN, accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      // 1 hr
      maxAge: 60 * 60 * 1000
    });
    console.log('New access token generated');
    return res.status(200).send('<h1>New access token generated!</h1>');
  // Invalid refreshToken, clear cookie and send to home page
  } catch (err) {
    console.log('Invalid refresh token');
    res.clearCookie(MY_REFRESH_TOKEN);
    return res.redirect('/');
  }
});

/**
 * Authorization middleware
 */
app.use((req: Request, res: Response, next) => {
  console.log('Authenticating request');
  // Attempt to validate access token. If token is valid, send to next middleware in stack
  const accessToken = req.cookies[MY_ACCESS_TOKEN];
  // No access token provided
  if (!accessToken) {
    console.log('No access token provided');
    return res.redirect('/');
  }

  // Validate access token
  try {
    const user = jwt.verify(accessToken, SECRET);
    res.locals.user = user;
    console.log('Access token valid');
    return next();
  // Token is no longer valid, clear token and attempt to get a new token with the refresh token
  } catch (err) {
    console.log('Access token invalid, need to get a new one');
    res.clearCookie(MY_ACCESS_TOKEN);
    return res.status(401).send('<h1>Unauthorized</h1>');
  }
});

/**
 * Protect route with profile information
 */
app.get('/profile', (req, res) => {
  const {username} = res.locals.user;
  return res.send(`<h1>Hello ${username}!</h1>`);
});

/**
 * Listen on port
 */
app.listen(PORT, () => {
  console.log(`Server listening on port: ${PORT}`);
});