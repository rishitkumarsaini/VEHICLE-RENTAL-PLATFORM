# CityFlex Rentals — patched existing project

This package keeps the existing single-file CityFlex frontend and its existing rental modules, and patches its Express/MySQL backend to line up with the frontend routes and role model.

## Run it on macOS

1. Extract the project folder and open it in VS Code.
2. In Terminal, run `cp .env.example .env`.
3. Edit `.env` with your actual MySQL username/password. If you want to choose the admin password in advance, set `ADMIN_PASSWORD` to a unique password of at least 12 characters before the first server start.
4. Run `npm install` and then `npm start`.
5. Open `http://localhost:3000`.

If there is no active administrator and `ADMIN_PASSWORD` is not set, the server creates an administrator with username `admin` and email from `ADMIN_EMAIL`, generates a strong random password, and prints it once to the Terminal. Copy/save it immediately. It is not stored in plaintext. Subsequent starts will not print it again.

The server automatically creates the database and tables. Insecure legacy demo accounts (`Admin@123`, `Owner@123`, `Customer@123`) created by the old prototype are disabled during startup if they still have those exact default passwords. The schema no longer seeds demo credentials.

## Important security notes

- Customer and owner registrations are allowed; public admin registration is blocked.
- The browser receives an HttpOnly SameSite session cookie; role access is checked on the server.
- Passwords are stored using Node's scrypt hash and are never returned by API endpoints.
- The public vehicle catalog only exposes approved, available vehicles and omits private pickup addresses and registration numbers.
- This is a local prototype. Use HTTPS, durable session storage, rate limiting, secure database credentials and review security before public deployment.
# VEHICLE-RENTAL-PLATFORM
