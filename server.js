require("dotenv").config();
const express = require("express");
const mysql = require("mysql2/promise");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { spawn, execFileSync } = require("child_process");

const app = express();
const PORT = Number(process.env.PORT || 3000);

const DB_CONFIG = {
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  port: Number(process.env.DB_PORT || 3306)
};
const DB_NAME = process.env.DB_NAME || "cityflex_db";

let pool;

// Serve the single-page frontend only; never expose server.js, schema.sql, .env or package files.
app.use(express.json({ limit: "15mb" }));
app.disable("x-powered-by");
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  next();
});

const SESSION_COOKIE = "cityflex_session";
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const sessions = new Map();
const loginAttempts = new Map();
const otpAttempts = new Map();
function allowAttempt(store, key, max, windowMs) {
  const now = Date.now();
  let entry = store.get(key);
  if (!entry || entry.until <= now) {
    if (store.size >= 10000) {
      for (const [k, v] of store) if (v.until <= now) store.delete(k);
      if (store.size >= 10000) return false;
    }
    entry = { count: 0, until: now + windowMs };
    store.set(key, entry);
  }
  if (entry.count >= max) return false;
  entry.count += 1;
  return true;
}
function hideHandoverOtp(booking) {
  const { handoverOtp, ...safe } = booking;
  return safe;
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(String(password), salt, 64).toString("hex");
  return `scrypt$${salt}$${hash}`;
}

function verifyPassword(password, stored) {
  if (typeof stored !== "string") return false;
  if (!stored.startsWith("scrypt$")) return stored === String(password); // legacy accounts are re-hashed at successful login
  const parts = stored.split("$");
  if (parts.length !== 3) return false;
  try {
    const actual = crypto.scryptSync(String(password), parts[1], 64);
    const expected = Buffer.from(parts[2], "hex");
    return expected.length === actual.length && crypto.timingSafeEqual(actual, expected);
  } catch (_) {
    return false;
  }
}

function getCookie(req, name) {
  const header = req.headers.cookie || "";
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    if (part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return "";
}

function setSessionCookie(res, token) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  res.setHeader("Set-Cookie", `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}${secure}`);
}

function clearSessionCookie(res) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  res.setHeader("Set-Cookie", `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}`);
}

async function createSession(req, res, userId) {
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, { userId, expiresAt: Date.now() + SESSION_TTL_MS });
  const previous = getCookie(req, SESSION_COOKIE);
  if (previous) sessions.delete(previous);
  setSessionCookie(res, token);
}

// Resolve the HttpOnly session cookie and enforce role / ownership permissions for every API.
app.use(async (req, res, next) => {
  try {
    const token = getCookie(req, SESSION_COOKIE);
    const session = token ? sessions.get(token) : null;
    if (session && session.expiresAt > Date.now()) {
      const [[user]] = await pool.query(
        "SELECT user_id, role, username, email, is_active FROM users WHERE user_id = ? LIMIT 1",
        [session.userId]
      );
      if (user && Number(user.is_active) === 1) req.user = user;
      else sessions.delete(token);
    } else if (token) {
      sessions.delete(token);
    }

    if (!req.path.startsWith("/api/")) return next();

    const method = req.method.toUpperCase();
    const route = req.path.slice(4); // remove /api
    // Refuse cross-origin state changes, including public registration/contact forms.
    if (["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
      const origin = req.get("origin");
      if (origin) {
        try {
          if (new URL(origin).host !== req.get("host")) {
            return res.status(403).json({ success: false, message: "Cross-origin request rejected." });
          }
        } catch (_) {
          return res.status(403).json({ success: false, message: "Invalid request origin." });
        }
      }
    }

    const publicRoutes = new Set([
      "POST /auth/login", "POST /admin/login", "POST /auth/register",
      "POST /auth/logout", "GET /vehicles", "GET /sale-listings", "POST /inquiries", "GET /settings"
    ]);
    if (publicRoutes.has(`${method} ${route}`)) return next();

    if (!req.user) return res.status(401).json({ success: false, message: "Please sign in first." });
    const role = req.user.role;
    const isAdmin = role === "ADMIN";

    if (route === "/me" && method === "GET") return next();
    if (route.startsWith("/admin/")) {
      if (!isAdmin) return res.status(403).json({ success: false, message: "Administrator access required." });
      return next();
    }
    if (route.startsWith("/owner/")) {
      if (role !== "OWNER") return res.status(403).json({ success: false, message: "Vehicle owner access required." });
      return next();
    }
    if (route === "/my/bookings" && method === "GET") {
      if (role !== "CUSTOMER") return res.status(403).json({ success: false, message: "Customer access required." });
      return next();
    }
    if (route === "/my/driver-bookings" && method === "GET") {
      if (role !== "CUSTOMER") return res.status(403).json({ success: false, message: "Customer access required." });
      return next();
    }
    if (route === "/my/inquiries" && method === "GET") {
      if (role !== "CUSTOMER") return res.status(403).json({ success: false, message: "Customer access required." });
      return next();
    }
    if (route.startsWith("/profile/") && method === "PUT") {
      const requestedUserId = decodeURIComponent(route.slice("/profile/".length));
      if (!isAdmin && requestedUserId !== req.user.user_id) return res.status(403).json({ success: false, message: "You can only update your own profile." });
      if (isAdmin && requestedUserId !== req.user.user_id) return res.status(403).json({ success: false, message: "Administrators can edit their own profile through this form." });
      return next();
    }
    if (route === "/vehicles" && method === "POST") {
      if (!isAdmin && role !== "OWNER") return res.status(403).json({ success: false, message: "Only administrators and vehicle owners can add vehicles." });
      return next();
    }
    if (route.startsWith("/vehicles/") && (method === "PATCH" || method === "DELETE")) {
      if (!isAdmin) return res.status(403).json({ success: false, message: "Administrator access required." });
      return next();
    }
    if (route === "/sale-listings" && method === "POST") {
      if (role !== "OWNER") return res.status(403).json({ success: false, message: "Only verified owner accounts can publish sale listings." });
      return next();
    }
    if (route === "/inquiries" && method === "GET") {
      if (!isAdmin) return res.status(403).json({ success: false, message: "Administrator access required." });
      return next();
    }
    if (route === "/bookings" && method === "GET") {
      if (!isAdmin) return res.status(403).json({ success: false, message: "Administrator access required." });
      return next();
    }
    if (route === "/bookings" && method === "POST") {
      if (role !== "CUSTOMER") return res.status(403).json({ success: false, message: "Sign in as a customer to make a booking." });
      return next();
    }
    if (/^\/bookings\/[^/]+\/extend$/.test(route) && method === "PATCH") {
      if (!isAdmin && role !== "CUSTOMER") return res.status(403).json({ success: false, message: "Booking access denied." });
      return next();
    }
    if (/^\/bookings\/[^/]+\/verify-otp$/.test(route) && method === "PATCH") {
      if (!isAdmin && role !== "OWNER") return res.status(403).json({ success: false, message: "Owner or administrator access required." });
      return next();
    }
    if (route === "/driver-bookings" && method === "GET") {
      if (!isAdmin) return res.status(403).json({ success: false, message: "Administrator access required." });
      return next();
    }
    if (route === "/driver-bookings" && method === "POST") {
      if (role !== "CUSTOMER") return res.status(403).json({ success: false, message: "Sign in as a customer to request a driver." });
      return next();
    }

    return res.status(404).json({ success: false, message: "API endpoint not found." });
  } catch (err) {
    console.error("Request authorization error:", err.message);
    return res.status(500).json({ success: false, message: "Request authorization failed." });
  }
});

async function resolveMySqlConfig() {
  try {
    const testConn = await mysql.createConnection(DB_CONFIG);
    await testConn.end();
    return DB_CONFIG;
  } catch (primaryErr) {
    if (process.env.NODE_ENV === "production") throw primaryErr;
    const localSocket = process.env.DB_SOCKET || "/tmp/mysql_demo.sock";
    const localDataDir = "/tmp/mysql_demo_data";
    const mysqldBin = "/usr/local/mysql/bin/mysqld";
    const fallbackConfig = { user: "root", password: "", socketPath: localSocket };

    try {
      const sockConn = await mysql.createConnection(fallbackConfig);
      await sockConn.end();
      return fallbackConfig;
    } catch (_) {}

    if (fs.existsSync(mysqldBin)) {
      console.log("Starting local MySQL server (/usr/local/mysql/bin/mysqld)...");
      if (!fs.existsSync(localDataDir)) {
        fs.mkdirSync(localDataDir, { recursive: true });
        execFileSync(mysqldBin, [
          "--initialize-insecure",
          `--datadir=${localDataDir}`,
          "--basedir=/usr/local/mysql"
        ]);
      }

      const child = spawn(
        mysqldBin,
        [
          `--datadir=${localDataDir}`,
          "--basedir=/usr/local/mysql",
          `--socket=${localSocket}`,
          "--port=3307",
          "--pid-file=/tmp/mysql_demo.pid",
          "--mysqlx=0",
          "--log-error=/tmp/mysql_demo.err"
        ],
        { detached: true, stdio: "ignore" }
      );
      child.unref();

      for (let i = 0; i < 15; i++) {
        await new Promise((r) => setTimeout(r, 1000));
        try {
          const sockConn = await mysql.createConnection(fallbackConfig);
          await sockConn.end();
          return fallbackConfig;
        } catch (_) {}
      }
    }
    throw primaryErr;
  }
}

async function initDatabase() {
  const activeConfig = await resolveMySqlConfig();
  const bootstrapConn = await mysql.createConnection(activeConfig);
  await bootstrapConn.query(
    `CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`
  );
  await bootstrapConn.end();

  pool = mysql.createPool({
    ...activeConfig,
    database: DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  });

  // 1. users table (Authentication & Role Credentials)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      user_id VARCHAR(64) PRIMARY KEY,
      role ENUM('CUSTOMER', 'OWNER', 'ADMIN') NOT NULL,
      username VARCHAR(100) NOT NULL UNIQUE,
      email VARCHAR(255) NOT NULL UNIQUE,
      password_hash VARCHAR(255) NOT NULL,
      is_active TINYINT(1) NOT NULL DEFAULT 1,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB
  `);

  // 2. customer_profiles table (Separate table for Customer profile data)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS customer_profiles (
      user_id VARCHAR(64) PRIMARY KEY,
      full_name VARCHAR(255) NOT NULL DEFAULT '',
      phone VARCHAR(64) NOT NULL DEFAULT '',
      driving_licence VARCHAR(100) NOT NULL DEFAULT '',
      city VARCHAR(100) NOT NULL DEFAULT 'Chandigarh',
      address VARCHAR(500) NOT NULL DEFAULT '',
      dl_verified TINYINT(1) NOT NULL DEFAULT 1,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      CONSTRAINT fk_customer_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
    ) ENGINE=InnoDB
  `);

  // 3. owner_profiles table (Separate table for Personal Vehicle Owner / Host profile data)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS owner_profiles (
      user_id VARCHAR(64) PRIMARY KEY,
      host_name VARCHAR(255) NOT NULL DEFAULT '',
      phone VARCHAR(64) NOT NULL DEFAULT '',
      city VARCHAR(100) NOT NULL DEFAULT 'Ludhiana',
      garage_address VARCHAR(500) NOT NULL DEFAULT '',
      payout_upi_or_bank VARCHAR(255) NOT NULL DEFAULT '',
      delivery_enabled TINYINT(1) NOT NULL DEFAULT 1,
      delivery_radius_km INT NOT NULL DEFAULT 15,
      lead_time_hours INT NOT NULL DEFAULT 4,
      kyc_verified TINYINT(1) NOT NULL DEFAULT 1,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      CONSTRAINT fk_owner_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
    ) ENGINE=InnoDB
  `);

  // 4. admin_profiles table (Separate table for Administrator profile data)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS admin_profiles (
      user_id VARCHAR(64) PRIMARY KEY,
      admin_name VARCHAR(255) NOT NULL DEFAULT '',
      designation VARCHAR(150) NOT NULL DEFAULT 'Platform Administrator',
      phone VARCHAR(64) NOT NULL DEFAULT '',
      operating_cluster VARCHAR(150) NOT NULL DEFAULT 'Punjab & Chandigarh/Tricity',
      employee_code VARCHAR(64) NOT NULL DEFAULT 'ADM-001',
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      CONSTRAINT fk_admin_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
    ) ENGINE=InnoDB
  `);

  // 5. vehicles table (Empty by default — Admin and Owners add their own vehicles & images)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS vehicles (
      id VARCHAR(64) PRIMARY KEY,
      owner_user_id VARCHAR(64) NULL,
      ownerType ENUM('PLATFORM', 'PARTNER', 'PRIVATE_OWNER') NOT NULL DEFAULT 'PLATFORM',
      ownerName VARCHAR(255) NOT NULL DEFAULT '',
      name VARCHAR(255) NOT NULL,
      registrationNo VARCHAR(64) NOT NULL DEFAULT '',
      category ENUM('car', 'bike', 'scooter') NOT NULL DEFAULT 'car',
      bodyType VARCHAR(100) NOT NULL DEFAULT 'SUV',
      fuelType ENUM('petrol', 'diesel', 'electric', 'cng', 'hybrid') NOT NULL DEFAULT 'petrol',
      evBattery VARCHAR(64) NULL,
      evRange VARCHAR(100) NULL,
      transmission VARCHAR(64) NOT NULL DEFAULT 'Manual',
      seats INT NOT NULL DEFAULT 5,
      city VARCHAR(100) NOT NULL DEFAULT 'Chandigarh',
      pickupHub VARCHAR(255) NOT NULL DEFAULT 'Central Hub',
      dailyRate DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
      hourlyRate DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
      weekdayPassRate DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
      subscriptionMonthlyRate DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
      deposit DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
      includedKmPerDay INT NOT NULL DEFAULT 150,
      extraKmRate DECIMAL(10, 2) NOT NULL DEFAULT 10.00,
      deliveryEligible TINYINT(1) NOT NULL DEFAULT 1,
      ownerPickupAddress VARCHAR(500) NOT NULL DEFAULT '',
      approvalStatus ENUM('APPROVED', 'PENDING', 'REJECTED') NOT NULL DEFAULT 'APPROVED',
      operationalStatus ENUM('AVAILABLE', 'ACTIVE_RENTAL', 'MAINTENANCE') NOT NULL DEFAULT 'AVAILABLE',
      rating DECIMAL(3, 2) NOT NULL DEFAULT 5.00,
      trips INT NOT NULL DEFAULT 0,
      image LONGTEXT NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      CONSTRAINT fk_vehicle_owner FOREIGN KEY (owner_user_id) REFERENCES users(user_id) ON DELETE SET NULL
    ) ENGINE=InnoDB
  `);

  // 6. sale_listings table (Personal vehicles listed for permanent sale)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sale_listings (
      id VARCHAR(64) PRIMARY KEY,
      owner_user_id VARCHAR(64) NULL,
      sellerName VARCHAR(255) NOT NULL,
      sellerCity VARCHAR(100) NOT NULL,
      vehicleName VARCHAR(255) NOT NULL,
      modelYear INT NOT NULL DEFAULT 2023,
      odometerKm INT NOT NULL DEFAULT 10000,
      conditionNote VARCHAR(255) NOT NULL DEFAULT 'Excellent',
      askingPrice VARCHAR(100) NOT NULL,
      negotiable TINYINT(1) NOT NULL DEFAULT 1,
      image LONGTEXT NOT NULL,
      status ENUM('AVAILABLE', 'SOLD') NOT NULL DEFAULT 'AVAILABLE',
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      CONSTRAINT fk_sale_owner FOREIGN KEY (owner_user_id) REFERENCES users(user_id) ON DELETE SET NULL
    ) ENGINE=InnoDB
  `);

  // 7. bookings table (Customer rental bookings)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS bookings (
      id VARCHAR(64) PRIMARY KEY,
      customer_user_id VARCHAR(64) NULL,
      owner_user_id VARCHAR(64) NULL,
      vehicleId VARCHAR(64) NOT NULL,
      vehicleName VARCHAR(255) NOT NULL,
      customerName VARCHAR(255) NOT NULL,
      customerPhone VARCHAR(64) NOT NULL,
      customerEmail VARCHAR(255) NOT NULL,
      customerDl VARCHAR(100) NOT NULL,
      plan VARCHAR(255) NOT NULL,
      days INT NOT NULL DEFAULT 1,
      dates VARCHAR(255) NOT NULL,
      pickupCity VARCHAR(100) NOT NULL,
      pickupMode VARCHAR(255) NOT NULL,
      deliveryAddress VARCHAR(500) NULL,
      returnMode VARCHAR(255) NOT NULL,
      partnerName VARCHAR(255) NULL,
      deliveryStatus VARCHAR(100) NOT NULL DEFAULT 'READY FOR HANDOVER',
      bookingStatus VARCHAR(100) NOT NULL DEFAULT 'CONFIRMED',
      paymentStatus VARCHAR(100) NOT NULL DEFAULT 'NOT PROCESSED (Demo)',
      rentalCharge DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
      deliveryFee DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
      returnFee DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
      discountAmount DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
      gstTax DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
      depositAmount DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
      quotedTotal DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
      platformCommission DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
      hostPayout DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
      handoverOtp VARCHAR(16) NOT NULL,
      startOdometer INT NULL,
      createdAt VARCHAR(64) NOT NULL,
      recordedAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB
  `);

  // Backward-compatible migrations for databases created by older CityFlex versions.
  // Add returnFee first because the discountAmount migration is placed after it.
  // Do not use DROP/RECREATE: existing bookings are preserved.
  const [returnFeeColumns] = await pool.query("SHOW COLUMNS FROM bookings LIKE 'returnFee'");
  if (returnFeeColumns.length === 0) {
    await pool.query("ALTER TABLE bookings ADD COLUMN returnFee DECIMAL(10, 2) NOT NULL DEFAULT 0.00");
  }

  const [discountColumns] = await pool.query("SHOW COLUMNS FROM bookings LIKE 'discountAmount'");
  if (discountColumns.length === 0) {
    await pool.query("ALTER TABLE bookings ADD COLUMN discountAmount DECIMAL(10, 2) NOT NULL DEFAULT 0.00 AFTER returnFee");
  }

  // 8. driver_requests table (Rent-a-Driver bookings)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS driver_requests (
      id INT AUTO_INCREMENT PRIMARY KEY,
      customer_user_id VARCHAR(64) NULL,
      customerName VARCHAR(255) NOT NULL DEFAULT '',
      mode ENUM('MODE_A', 'MODE_B') NOT NULL DEFAULT 'MODE_A',
      city VARCHAR(100) NOT NULL,
      servicePackage VARCHAR(100) NOT NULL,
      vehicleClass VARCHAR(100) NULL,
      pickupLocation VARCHAR(255) NOT NULL,
      destinationLocation VARCHAR(255) NOT NULL,
      pickupDateTime VARCHAR(100) NULL,
      customerMobile VARCHAR(64) NOT NULL,
      specialNotes TEXT NULL,
      quotedTotal DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
      status VARCHAR(64) NOT NULL DEFAULT 'CONFIRMED',
      createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB
  `);

  // 9. inquiries table (Buy/Sell Marketplace inquiries)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS inquiries (
      id INT AUTO_INCREMENT PRIMARY KEY,
      saleListingId VARCHAR(64) NULL,
      customer_user_id VARCHAR(64) NULL,
      owner_user_id VARCHAR(64) NULL,
      vehicleName VARCHAR(255) NOT NULL,
      askingPrice VARCHAR(100) NULL,
      sellerName VARCHAR(255) NULL,
      buyerName VARCHAR(255) NOT NULL,
      buyerPhone VARCHAR(64) NOT NULL,
      preferredViewingDate VARCHAR(64) NOT NULL,
      inquiryMessage TEXT NULL,
      inquiryStatus VARCHAR(64) NOT NULL DEFAULT 'VIEWING_REQUESTED',
      createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB
  `);

  // 10. platform_settings table
  await pool.query(`
    CREATE TABLE IF NOT EXISTS platform_settings (
      setting_key VARCHAR(64) PRIMARY KEY,
      setting_value VARCHAR(255) NOT NULL,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB
  `);

  // No default accounts or passwords are inserted. Legacy demo credentials are disabled,
  // then a private administrator account is bootstrapped securely if needed.
  await pool.query(`
    INSERT IGNORE INTO platform_settings (setting_key, setting_value) VALUES
      ('commission_rate', '12'),
      ('oneway_hub_fee', '450'),
      ('doorstep_delivery_fee', '199')
  `);
  await disableLegacyDemoAccounts();
  await bootstrapAdminAccount();
}

// Return only the safe account and role-specific profile. Never expose password_hash.
async function getUserWithProfile(userId) {
  const [[user]] = await pool.query(
    "SELECT user_id, role, username, email, is_active, created_at FROM users WHERE user_id = ?",
    [userId]
  );
  if (!user) return null;
  let profile = {};
  if (user.role === "CUSTOMER") {
    const [[p]] = await pool.query("SELECT * FROM customer_profiles WHERE user_id = ?", [userId]);
    profile = p || {};
  } else if (user.role === "OWNER") {
    const [[p]] = await pool.query("SELECT * FROM owner_profiles WHERE user_id = ?", [userId]);
    profile = p || {};
  } else if (user.role === "ADMIN") {
    const [[p]] = await pool.query("SELECT * FROM admin_profiles WHERE user_id = ?", [userId]);
    profile = p || {};
  }
  return { ...user, id: user.user_id, status: Number(user.is_active) === 1 ? "ACTIVE" : "DISABLED", profile };
}

async function disableLegacyDemoAccounts() {
  const legacy = [
    ["usr-admin-1", "Admin@123"],
    ["usr-owner-1", "Owner@123"],
    ["usr-cust-1", "Customer@123"]
  ];
  for (const [userId, oldPassword] of legacy) {
    const [[user]] = await pool.query("SELECT user_id, username, email, password_hash FROM users WHERE user_id = ?", [userId]);
    // Disable legacy demo accounts whether their old default password is still plaintext
    // or was already converted to a scrypt hash by the previous prototype.
    if (user && (user.password_hash === oldPassword || verifyPassword(oldPassword, user.password_hash))) {
      const tombstone = `disabled-${userId}-${crypto.randomBytes(4).toString("hex")}`;
      await pool.query(
        "UPDATE users SET username = ?, email = ?, password_hash = ?, is_active = 0 WHERE user_id = ?",
        [tombstone, `${tombstone}@invalid.local`, hashPassword(crypto.randomBytes(32).toString("hex")), userId]
      );
      console.warn(`Disabled insecure legacy demo account: ${userId}`);
    }
  }
}

async function bootstrapAdminAccount() {
  const [[existingAdmin]] = await pool.query(
    "SELECT user_id FROM users WHERE role = 'ADMIN' AND is_active = 1 LIMIT 1"
  );
  if (existingAdmin) return;

  const email = String(process.env.ADMIN_EMAIL || "admin@cityflex.in").trim().toLowerCase();
  const username = String(process.env.ADMIN_USERNAME || "admin").trim();
  const configuredPassword = String(process.env.ADMIN_PASSWORD || "");
  const password = configuredPassword || crypto.randomBytes(18).toString("base64url");
  if (password.length < 12) throw new Error("ADMIN_PASSWORD must contain at least 12 characters.");

  const [[collision]] = await pool.query(
    "SELECT user_id FROM users WHERE LOWER(email) = ? OR LOWER(username) = ? LIMIT 1",
    [email, username.toLowerCase()]
  );
  if (collision) throw new Error("Admin email/username already exists. Set ADMIN_EMAIL and ADMIN_USERNAME to unique values in .env.");

  const userId = `usr-admin-${crypto.randomUUID()}`;
  await pool.query(
    "INSERT INTO users (user_id, role, username, email, password_hash, is_active) VALUES (?, 'ADMIN', ?, ?, ?, 1)",
    [userId, username, email, hashPassword(password)]
  );
  await pool.query(
    "INSERT INTO admin_profiles (user_id, admin_name, designation, operating_cluster, employee_code) VALUES (?, '', 'Platform Administrator', 'Punjab & Chandigarh/Tricity', 'ADM-001')",
    [userId]
  );
  console.log("\nCityFlex administrator account created.");
  console.log(`Admin email: ${email}`);
  console.log(`Admin username: ${username}`);
  if (!configuredPassword) {
    console.log(`Temporary admin password (copy it now): ${password}`);
    console.log("The temporary password is not stored in plaintext and will not be shown again.\n");
  } else {
    console.log("Admin password read from the ADMIN_PASSWORD environment variable.\n");
  }
}

// ============================================================================
// AUTH & PROFILE ROUTES
// ============================================================================
async function loginHandler(req, res) {
  try {
    const body = req.body || {};
    const identifier = String(body.identifier || body.email || body.username || "").trim().toLowerCase();
    const password = String(body.password || "");
    const requestedRole = String(body.role || (req.path === "/api/admin/login" ? "ADMIN" : "")).toUpperCase();
    if (!identifier || !password) return res.status(400).json({ success: false, message: "Email/username and password are required." });
    if (requestedRole && !["CUSTOMER", "OWNER", "ADMIN"].includes(requestedRole)) {
      return res.status(400).json({ success: false, message: "Invalid account role." });
    }

    if (identifier.length > 255 || password.length > 1024) return res.status(400).json({ success: false, message: "Invalid credential length." });
    if (!allowAttempt(loginAttempts, identifier, 10, 15 * 60 * 1000)) {
      return res.status(429).json({ success: false, message: "Too many login attempts. Try again in 15 minutes." });
    }
    const [[user]] = await pool.query(
      "SELECT * FROM users WHERE LOWER(email) = ? OR LOWER(username) = ? LIMIT 1",
      [identifier, identifier]
    );
    if (!user || Number(user.is_active) !== 1 || (requestedRole && user.role !== requestedRole)) {
      return res.status(401).json({ success: false, message: "Invalid credentials for this login portal." });
    }
    if (!verifyPassword(password, user.password_hash)) {
      return res.status(401).json({ success: false, message: "Invalid credentials for this login portal." });
    }
    if (!String(user.password_hash).startsWith("scrypt$")) {
      await pool.query("UPDATE users SET password_hash = ? WHERE user_id = ?", [hashPassword(password), user.user_id]);
    }
    await createSession(req, res, user.user_id);
    loginAttempts.delete(identifier);
    return res.json({ success: true, user: await getUserWithProfile(user.user_id) });
  } catch (err) {
    console.error("Login error:", err.message);
    return res.status(500).json({ success: false, message: "Server error during login." });
  }
}

app.post("/api/auth/login", loginHandler);
app.post("/api/admin/login", loginHandler);

app.get("/api/me", async (req, res) => {
  if (!req.user) return res.status(401).json({ success: false, message: "Not signed in." });
  const user = await getUserWithProfile(req.user.user_id);
  if (!user) return res.status(401).json({ success: false, message: "Session is no longer valid." });
  res.json({ success: true, user });
});

app.post("/api/auth/logout", (req, res) => {
  const token = getCookie(req, SESSION_COOKIE);
  if (token) sessions.delete(token);
  clearSessionCookie(res);
  res.json({ success: true });
});

app.post("/api/auth/register", async (req, res) => {
  const connection = await pool.getConnection();
  try {
    const body = req.body || {};
    const role = String(body.role || "CUSTOMER").toUpperCase();
    const username = String(body.username || String(body.email || "").split("@")[0] || "").trim();
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    const name = String(body.name || body.fullName || body.full_name || "").trim();
    const phone = String(body.phone || "").trim();
    const city = String(body.city || "Chandigarh").trim();
    const extraField = String(body.extraField || "").trim();

    if (!["CUSTOMER", "OWNER"].includes(role)) {
      return res.status(403).json({ success: false, message: "Administrator accounts cannot be created through public registration." });
    }
    if (!username || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 10 || name.length < 2) {
      return res.status(400).json({ success: false, message: "Enter a valid name, email, username, and password of at least 10 characters." });
    }

    const userId = `usr-${role.toLowerCase()}-${crypto.randomUUID()}`;
    await connection.beginTransaction();
    await connection.query(
      "INSERT INTO users (user_id, role, username, email, password_hash, is_active) VALUES (?, ?, ?, ?, ?, 1)",
      [userId, role, username, email, hashPassword(password)]
    );
    if (role === "CUSTOMER") {
      await connection.query(
        "INSERT INTO customer_profiles (user_id, full_name, phone, driving_licence, city) VALUES (?, ?, ?, ?, ?)",
        [userId, name, phone, extraField, city]
      );
    } else {
      await connection.query(
        "INSERT INTO owner_profiles (user_id, host_name, phone, city, garage_address) VALUES (?, ?, ?, ?, ?)",
        [userId, name, phone, city, extraField]
      );
    }
    await connection.commit();
    await createSession(req, res, userId);
    return res.status(201).json({ success: true, user: await getUserWithProfile(userId) });
  } catch (err) {
    await connection.rollback();
    console.error("Registration error:", err.message);
    return res.status(err.code === "ER_DUP_ENTRY" ? 409 : 400).json({
      success: false,
      message: err.code === "ER_DUP_ENTRY" ? "Username or email already exists." : "Registration failed. Check the details and try again."
    });
  } finally {
    connection.release();
  }
});

app.put("/api/profile/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const [[user]] = await pool.query("SELECT * FROM users WHERE user_id = ?", [userId]);
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found." });
    }

    const b = req.body || {};
    if (user.role === "CUSTOMER") {
      await pool.query(
        `UPDATE customer_profiles
         SET full_name = ?, phone = ?, driving_licence = ?, city = ?, address = ?
         WHERE user_id = ?`,
        [
          b.full_name || "",
          b.phone || "",
          b.driving_licence || "",
          b.city || "Chandigarh",
          b.address || "",
          userId
        ]
      );
    } else if (user.role === "OWNER") {
      await pool.query(
        `UPDATE owner_profiles
         SET host_name = ?, phone = ?, city = ?, garage_address = ?, payout_upi_or_bank = ?,
             delivery_enabled = ?, delivery_radius_km = ?, lead_time_hours = ?
         WHERE user_id = ?`,
        [
          b.host_name || "",
          b.phone || "",
          b.city || "Ludhiana",
          b.garage_address || "",
          b.payout_upi_or_bank || "",
          b.delivery_enabled !== undefined ? (b.delivery_enabled ? 1 : 0) : 1,
          Number(b.delivery_radius_km) || 15,
          Number(b.lead_time_hours) || 4,
          userId
        ]
      );
    } else if (user.role === "ADMIN") {
      await pool.query(
        `UPDATE admin_profiles
         SET admin_name = ?, designation = ?, phone = ?, operating_cluster = ?, employee_code = ?
         WHERE user_id = ?`,
        [
          b.admin_name || "",
          b.designation || "Platform Administrator",
          b.phone || "",
          b.operating_cluster || "Punjab & Chandigarh/Tricity",
          b.employee_code || "ADM-001",
          userId
        ]
      );
    }

    const updated = await getUserWithProfile(userId);
    res.json({ success: true, user: updated });
  } catch (err) {
    console.error("Profile update error:", err);
    res.status(500).json({ success: false, message: "Failed to update profile." });
  }
});

app.get("/api/settings", async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT setting_key, setting_value FROM platform_settings WHERE setting_key IN ('commission_rate', 'oneway_hub_fee', 'doorstep_delivery_fee')"
    );
    const values = Object.fromEntries(rows.map((row) => [row.setting_key, Number(row.setting_value) || 0]));
    res.json({ success: true, settings: {
      commissionRate: values.commission_rate ?? 12,
      oneWayFee: values.oneway_hub_fee ?? 450,
      doorstepFee: values.doorstep_delivery_fee ?? 199
    }});
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to load platform pricing." });
  }
});

app.get("/api/admin/settings", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT setting_key, setting_value FROM platform_settings");
    res.json({ success: true, settings: Object.fromEntries(rows.map((row) => [row.setting_key, row.setting_value])) });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to load admin settings." });
  }
});

app.put("/api/admin/settings", async (req, res) => {
  try {
    const body = req.body || {};
    const commissionRate = Number(body.commissionRate);
    const oneWayFee = Number(body.oneWayFee);
    const doorstepFee = Number(body.doorstepFee);
    if (![commissionRate, oneWayFee, doorstepFee].every(Number.isFinite) || commissionRate < 0 || commissionRate > 100 || oneWayFee < 0 || doorstepFee < 0) {
      return res.status(400).json({ success: false, message: "Enter valid commission and service fees." });
    }
    const pairs = [
      ["commission_rate", String(commissionRate)],
      ["oneway_hub_fee", String(oneWayFee)],
      ["doorstep_delivery_fee", String(doorstepFee)]
    ];
    for (const [key, value] of pairs) {
      await pool.query(
        "INSERT INTO platform_settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)",
        [key, value]
      );
    }
    res.json({ success: true, settings: { commissionRate, oneWayFee, doorstepFee } });
  } catch (err) {
    console.error("Save settings error:", err.message);
    res.status(500).json({ success: false, message: "Failed to save platform pricing." });
  }
});

app.get("/api/admin/users", async (req, res) => {
  try {
    const [users] = await pool.query(`
      SELECT u.user_id, u.role, u.username, u.email, u.is_active, u.created_at,
        COALESCE(cp.full_name, op.host_name, ap.admin_name, '') AS fullName,
        COALESCE(cp.phone, op.phone, ap.phone, '') AS phone,
        COALESCE(cp.city, op.city, ap.operating_cluster, '') AS city,
        COALESCE(cp.address, op.garage_address, ap.designation, '') AS address,
        COALESCE(cp.driving_licence, '') AS drivingLicence,
        COALESCE(op.delivery_radius_km, 0) AS deliveryRadiusKm,
        COALESCE(op.delivery_enabled, 0) AS deliveryEnabled,
        COALESCE(ap.employee_code, '') AS employeeCode
      FROM users u
      LEFT JOIN customer_profiles cp ON cp.user_id = u.user_id
      LEFT JOIN owner_profiles op ON op.user_id = u.user_id
      LEFT JOIN admin_profiles ap ON ap.user_id = u.user_id
      ORDER BY u.created_at DESC`);
    res.json({ success: true, users: users.map((u) => ({
      ...u, status: Number(u.is_active) === 1 ? "ACTIVE" : "DISABLED",
      createdAt: u.created_at, role: u.role
    })) });
  } catch (err) {
    console.error("Admin user directory error:", err.message);
    res.status(500).json({ success: false, message: "Failed to load accounts." });
  }
});

app.get("/api/admin/bookings", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT * FROM bookings ORDER BY recordedAt DESC");
    res.json({ success: true, bookings: rows.map(hideHandoverOtp) });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to fetch bookings." });
  }
});

app.get("/api/my/bookings", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT * FROM bookings WHERE customer_user_id = ? ORDER BY recordedAt DESC", [req.user.user_id]);
    res.json({ success: true, bookings: rows });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to fetch your bookings." });
  }
});

app.get("/api/owner/bookings", async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT DISTINCT b.*
       FROM bookings b
       LEFT JOIN vehicles v ON v.id = b.vehicleId
       WHERE v.owner_user_id = ? OR b.owner_user_id = ?
       ORDER BY b.recordedAt DESC`,
      [req.user.user_id, req.user.user_id]
    );
    res.json({ success: true, bookings: rows.map(hideHandoverOtp) });
  } catch (err) {
    console.error("Owner bookings error:", err.message);
    res.status(500).json({ success: false, message: "Failed to fetch owner bookings." });
  }
});

app.get("/api/my/driver-bookings", async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT * FROM driver_requests WHERE customer_user_id = ? ORDER BY createdAt DESC",
      [req.user.user_id]
    );
    res.json({ success: true, driverBookings: rows });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to fetch your driver requests." });
  }
});

app.get("/api/my/inquiries", async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT id, saleListingId, vehicleName, askingPrice, sellerName, buyerName, buyerPhone, preferredViewingDate, inquiryMessage, inquiryStatus, createdAt FROM inquiries WHERE customer_user_id = ? ORDER BY createdAt DESC",
      [req.user.user_id]
    );
    res.json({ success: true, inquiries: rows });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to fetch your inquiries." });
  }
});

// ============================================================================
// VEHICLES ROUTES (Admin & Personal Owner Vehicles)
// ============================================================================
async function insertVehicleRecord(body, user) {
  const b = body || {};
  const name = String(b.name || b.vehicleName || "").trim();
  if (!name) throw Object.assign(new Error("Vehicle name is required."), { status: 400 });
  const isOwner = user.role === "OWNER";
  const profileUser = await getUserWithProfile(user.user_id);
  const profile = profileUser?.profile || {};
  const id = `cf-${crypto.randomUUID()}`;
  const image = String(b.image || b.imageUrl || "");
  if (image.length > 14 * 1024 * 1024) throw Object.assign(new Error("Image is too large. Use an image under 10 MB."), { status: 400 });
  if (image && !/^https:\/\//i.test(image) && !/^data:image\/(png|jpe?g|webp|gif|svg\+xml);base64,/i.test(image)) {
    throw Object.assign(new Error("Use an HTTPS image URL or upload a supported image."), { status: 400 });
  }
  const dailyRate = Math.max(0, Number(b.dailyRate) || 0);
  const categoryRaw = String(b.category || "car").toLowerCase();
  const category = ["car", "bike", "scooter"].includes(categoryRaw) ? categoryRaw : "car";
  const fuelRaw = String(b.fuelType || b.fuel || "petrol").toLowerCase();
  const fuelType = ["petrol", "diesel", "electric", "cng", "hybrid"].includes(fuelRaw) ? fuelRaw : "petrol";
  const ownerType = isOwner ? "PRIVATE_OWNER" : "PLATFORM";
  const ownerId = isOwner ? user.user_id : null;
  const ownerName = isOwner ? (profile.host_name || user.username) : (profile.admin_name || "CityFlex Official Fleet");
  const approvalStatus = isOwner ? "PENDING" : "APPROVED";

  await pool.query(
    `INSERT INTO vehicles (
      id, owner_user_id, ownerType, ownerName, name, registrationNo, category, bodyType,
      fuelType, evBattery, evRange, transmission, seats, city, pickupHub, dailyRate,
      hourlyRate, weekdayPassRate, subscriptionMonthlyRate, deposit, includedKmPerDay,
      extraKmRate, deliveryEligible, ownerPickupAddress, approvalStatus, operationalStatus, image
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      id, ownerId, ownerType, ownerName, name,
      String(b.registrationNo || b.registrationNumber || "").trim(), category,
      String(b.bodyType || b.description || "Vehicle"), fuelType,
      b.evBattery || null, b.evRange || null, String(b.transmission || "Manual"),
      Math.max(1, Number(b.seats) || (category === "car" ? 5 : 2)),
      String(b.city || profile.city || "Chandigarh"), String(b.pickupHub || "Central Hub"), dailyRate,
      Math.max(0, Number(b.hourlyRate) || Math.round(dailyRate / 15)),
      Math.max(0, Number(b.weekdayPassRate) || Math.round(dailyRate * 3.1)),
      Math.max(0, Number(b.subscriptionMonthlyRate) || Math.round(dailyRate * 16.5)),
      Math.max(0, Number(b.deposit ?? b.securityDeposit) || 0),
      Math.max(1, Number(b.includedKmPerDay) || 150), Math.max(0, Number(b.extraKmRate) || 10),
      b.deliveryEligible === false || b.deliveryEligible === 0 ? 0 : 1,
      String(b.ownerPickupAddress || profile.garage_address || b.pickupHub || ""),
      approvalStatus, "AVAILABLE", image
    ]
  );
  const [[vehicle]] = await pool.query("SELECT * FROM vehicles WHERE id = ?", [id]);
  return vehicle;
}

app.get("/api/vehicles", async (req, res) => {
  try {
    // Public response excludes owner IDs, registration numbers and personal pickup addresses.
    const [rows] = await pool.query(`
      SELECT id, ownerType, ownerName, name, category, bodyType, fuelType, evBattery, evRange,
        transmission, seats, city, pickupHub, dailyRate, hourlyRate, weekdayPassRate,
        subscriptionMonthlyRate, deposit, includedKmPerDay, extraKmRate, deliveryEligible,
        approvalStatus, operationalStatus, rating, trips, image, created_at
      FROM vehicles WHERE approvalStatus = 'APPROVED' AND operationalStatus = 'AVAILABLE'
      ORDER BY created_at DESC`);
    res.json({ success: true, vehicles: rows });
  } catch (err) {
    console.error("Fetch vehicles error:", err.message);
    res.status(500).json({ success: false, message: "Failed to fetch vehicles." });
  }
});

app.get("/api/admin/vehicles", async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT * FROM vehicles WHERE operationalStatus <> 'MAINTENANCE' ORDER BY created_at DESC"
    );
    res.json({ success: true, vehicles: rows });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to fetch vehicles." });
  }
});

app.get("/api/owner/vehicles", async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT * FROM vehicles WHERE owner_user_id = ? AND operationalStatus <> 'MAINTENANCE' ORDER BY created_at DESC",
      [req.user.user_id]
    );
    res.json({ success: true, vehicles: rows });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to fetch owner vehicles." });
  }
});

async function updateVehicleRecord(req, res, ownerOnly) {
  try {
    const id = String(req.params.id || "");
    const b = req.body || {};
    const [[existing]] = await pool.query("SELECT * FROM vehicles WHERE id = ? LIMIT 1", [id]);
    if (!existing) return res.status(404).json({ success: false, message: "Vehicle not found." });
    if (ownerOnly && existing.owner_user_id !== req.user.user_id) {
      return res.status(403).json({ success: false, message: "You can edit only vehicles listed from your own account." });
    }

    const name = String(b.name || b.vehicleName || existing.name || "").trim();
    if (!name) return res.status(400).json({ success: false, message: "Vehicle name is required." });
    const categoryRaw = String(b.category || existing.category || "car").toLowerCase();
    const category = ["car", "bike", "scooter"].includes(categoryRaw) ? categoryRaw : existing.category;
    const fuelRaw = String(b.fuelType || b.fuel || existing.fuelType || "petrol").toLowerCase();
    const fuelType = ["petrol", "diesel", "electric", "cng", "hybrid"].includes(fuelRaw) ? fuelRaw : existing.fuelType;
    const imageCandidate = String(b.image || b.imageUrl || existing.image || "");
    if (imageCandidate.length > 14 * 1024 * 1024) {
      return res.status(400).json({ success: false, message: "Image is too large. Use an image under 10 MB." });
    }
    if (imageCandidate && !/^https:\/\//i.test(imageCandidate) && !/^data:image\/(png|jpe?g|webp|gif|svg\+xml);base64,/i.test(imageCandidate)) {
      return res.status(400).json({ success: false, message: "Use an HTTPS image URL or upload a supported image." });
    }
    const status = ownerOnly ? "PENDING" : ( ["APPROVED", "PENDING", "REJECTED"].includes(String(b.approvalStatus || existing.approvalStatus).toUpperCase()) ? String(b.approvalStatus || existing.approvalStatus).toUpperCase() : existing.approvalStatus );

    await pool.query(
      `UPDATE vehicles SET
        name = ?, registrationNo = ?, category = ?, bodyType = ?, fuelType = ?,
        evBattery = ?, evRange = ?, transmission = ?, seats = ?, city = ?, pickupHub = ?,
        dailyRate = ?, hourlyRate = ?, weekdayPassRate = ?, subscriptionMonthlyRate = ?,
        deposit = ?, includedKmPerDay = ?, extraKmRate = ?, deliveryEligible = ?,
        ownerPickupAddress = ?, approvalStatus = ?, image = ?
       WHERE id = ?`,
      [
        name,
        String(b.registrationNo || b.registrationNumber || existing.registrationNo || "").trim(),
        category,
        String(b.bodyType || b.description || existing.bodyType || "Vehicle"),
        fuelType,
        b.evBattery || existing.evBattery || null,
        b.evRange || existing.evRange || null,
        String(b.transmission || existing.transmission || "Manual"),
        Math.max(1, Number(b.seats) || Number(existing.seats) || (category === "car" ? 5 : 2)),
        String(b.city || existing.city || "Chandigarh"),
        String(b.pickupHub || existing.pickupHub || "Central Hub"),
        Math.max(0, Number(b.dailyRate ?? existing.dailyRate) || 0),
        Math.max(0, Number(b.hourlyRate ?? existing.hourlyRate) || 0),
        Math.max(0, Number(b.weekdayPassRate ?? existing.weekdayPassRate) || 0),
        Math.max(0, Number(b.subscriptionMonthlyRate ?? existing.subscriptionMonthlyRate) || 0),
        Math.max(0, Number(b.deposit ?? b.securityDeposit ?? existing.deposit) || 0),
        Math.max(1, Number(b.includedKmPerDay ?? existing.includedKmPerDay) || 150),
        Math.max(0, Number(b.extraKmRate ?? existing.extraKmRate) || 10),
        b.deliveryEligible === false || b.deliveryEligible === 0 ? 0 : (b.deliveryEligible === true || b.deliveryEligible === 1 ? 1 : Number(existing.deliveryEligible)),
        String(b.ownerPickupAddress || existing.ownerPickupAddress || b.pickupHub || ""),
        status,
        imageCandidate,
        id
      ]
    );
    const [[updated]] = await pool.query("SELECT * FROM vehicles WHERE id = ?", [id]);
    res.json({ success: true, vehicle: updated, id: updated.id, status: updated.approvalStatus });
  } catch (err) {
    console.error("Update vehicle error:", err.message);
    res.status(500).json({ success: false, message: "Failed to update vehicle." });
  }
}

app.patch("/api/admin/vehicles/:id", (req, res) => updateVehicleRecord(req, res, false));
app.patch("/api/owner/vehicles/:id", (req, res) => updateVehicleRecord(req, res, true));

app.delete("/api/owner/vehicles/:id", async (req, res) => {
  try {
    const [result] = await pool.query(
      "UPDATE vehicles SET approvalStatus = 'REJECTED', operationalStatus = 'MAINTENANCE' WHERE id = ? AND owner_user_id = ?",
      [String(req.params.id), req.user.user_id]
    );
    if (!result.affectedRows) return res.status(404).json({ success: false, message: "Your vehicle listing was not found." });
    res.json({ success: true, archived: true });
  } catch (err) {
    res.status(500).json({ success: false, message: "Could not remove this vehicle listing." });
  }
});

async function createVehicleRoute(req, res) {
  try {
    const vehicle = await insertVehicleRecord(req.body, req.user);
    res.status(201).json({ success: true, id: vehicle.id, status: vehicle.approvalStatus, vehicle });
  } catch (err) {
    console.error("Add vehicle error:", err.message);
    res.status(err.status || 500).json({ success: false, message: err.message || "Failed to add vehicle." });
  }
}
app.post("/api/vehicles", createVehicleRoute);
app.post("/api/admin/vehicles", createVehicleRoute);
app.post("/api/owner/vehicles", createVehicleRoute);

async function updateVehicleApproval(req, res, statusFromBody = false) {
  try {
    const { id } = req.params;
    const body = req.body || {};
    let status = String(statusFromBody ? body.status : body.approvalStatus || "APPROVED").toUpperCase();
    if (status === "ACTIVE") status = "APPROVED";
    if (status === "INACTIVE") {
      // Soft-archive the vehicle without deleting rows referenced by booking history.
      await pool.query(
        "UPDATE vehicles SET approvalStatus = 'REJECTED', operationalStatus = 'MAINTENANCE' WHERE id = ?",
        [id]
      );
    } else {
      if (!["APPROVED", "PENDING", "REJECTED"].includes(status)) {
        return res.status(400).json({ success: false, message: "Invalid vehicle approval status." });
      }
      await pool.query("UPDATE vehicles SET approvalStatus = ? WHERE id = ?", [status, id]);
      if (status === "APPROVED") await pool.query("UPDATE vehicles SET operationalStatus = 'AVAILABLE' WHERE id = ?", [id]);
    }
    const [[vehicle]] = await pool.query("SELECT * FROM vehicles WHERE id = ?", [id]);
    if (!vehicle) return res.status(404).json({ success: false, message: "Vehicle not found." });
    res.json({ success: true, vehicle });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to update vehicle status." });
  }
}
app.patch("/api/vehicles/:id/approval", (req, res) => updateVehicleApproval(req, res, false));
app.patch("/api/admin/vehicles/:id/status", (req, res) => updateVehicleApproval(req, res, true));

app.delete("/api/vehicles/:id", async (req, res) => {
  try {
    const [result] = await pool.query("DELETE FROM vehicles WHERE id = ?", [req.params.id]);
    if (!result.affectedRows) return res.status(404).json({ success: false, message: "Vehicle not found." });
    res.json({ success: true });
  } catch (err) {
    console.error("Delete vehicle error:", err.message);
    res.status(500).json({ success: false, message: "Failed to delete vehicle." });
  }
});

// ============================================================================
// SALE LISTINGS & INQUIRIES ROUTES
// ============================================================================
app.get("/api/sale-listings", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT id, sellerName, sellerCity, vehicleName, modelYear, odometerKm, conditionNote, askingPrice, negotiable, image, status, created_at FROM sale_listings WHERE status = 'AVAILABLE' ORDER BY created_at DESC");
    res.json({ success: true, saleListings: rows });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to fetch sale listings." });
  }
});

app.post("/api/sale-listings", async (req, res) => {
  try {
    const b = req.body || {};
    const id = b.id || `sale-${Date.now()}`;
    await pool.query(
      `INSERT INTO sale_listings (
        id, owner_user_id, sellerName, sellerCity, vehicleName,
        modelYear, odometerKm, conditionNote, askingPrice, negotiable, image
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        id,
        req.user.user_id,
        (await getUserWithProfile(req.user.user_id))?.profile?.host_name || req.user.username,
        b.sellerCity || (await getUserWithProfile(req.user.user_id))?.profile?.city || "Chandigarh",
        b.vehicleName || "",
        Number(b.modelYear) || 2023,
        Number(b.odometerKm) || 10000,
        b.conditionNote || "Excellent",
        b.askingPrice || "",
        b.negotiable ? 1 : 0,
        b.image || ""
      ]
    );
    const [[listing]] = await pool.query("SELECT * FROM sale_listings WHERE id = ?", [id]);
    res.status(201).json({ success: true, listing });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to create sale listing." });
  }
});

app.get("/api/inquiries", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT * FROM inquiries ORDER BY createdAt DESC");
    res.json({ success: true, inquiries: rows });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to fetch inquiries." });
  }
});

app.post("/api/inquiries", async (req, res) => {
  try {
    const b = req.body || {};
    const [result] = await pool.query(
      `INSERT INTO inquiries (
        saleListingId, customer_user_id, owner_user_id, vehicleName,
        askingPrice, sellerName, buyerName, buyerPhone, preferredViewingDate, inquiryMessage
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        b.saleListingId || null,
        req.user?.role === "CUSTOMER" ? req.user.user_id : null,
        null,
        b.vehicleName || "",
        b.askingPrice || "",
        b.sellerName || "",
        b.buyerName || "",
        b.buyerPhone || "",
        b.preferredViewingDate || "",
        b.inquiryMessage || ""
      ]
    );
    const [[inquiry]] = await pool.query("SELECT * FROM inquiries WHERE id = ?", [result.insertId]);
    res.status(201).json({ success: true, inquiry });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to save inquiry." });
  }
});

// ============================================================================
// BOOKINGS & DRIVER REQUESTS ROUTES
// ============================================================================
app.get("/api/bookings", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT * FROM bookings ORDER BY recordedAt DESC");
    res.json({ success: true, bookings: rows.map(hideHandoverOtp) });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to fetch bookings." });
  }
});

app.post("/api/bookings", async (req, res) => {
  try {
    const b = req.body || {};
    const vehicleId = String(b.vehicleId || "").trim();
    if (!vehicleId) return res.status(400).json({ success: false, message: "Select a vehicle first." });

    const [[bookingVehicle]] = await pool.query(
      `SELECT id, name, owner_user_id, dailyRate, deposit, approvalStatus, operationalStatus
       FROM vehicles WHERE id = ? LIMIT 1`,
      [vehicleId]
    );
    if (!bookingVehicle || bookingVehicle.approvalStatus !== "APPROVED" || bookingVehicle.operationalStatus !== "AVAILABLE") {
      return res.status(400).json({ success: false, message: "This vehicle is not currently available." });
    }

    const bookingUser = await getUserWithProfile(req.user.user_id);
    const bookingProfile = bookingUser?.profile || {};
    const calculatedDays = Math.max(1, Math.min(30, Number(b.days) || 1));
    const calculatedRental = Math.max(0, Number(bookingVehicle.dailyRate) || 0) * calculatedDays;
    const pickupMode = String(b.pickupMode || "OWNER_PICKUP").toUpperCase();
    const returnMode = String(b.returnMode || "OWNER_RETURN").toUpperCase();

    const [settingsRows] = await pool.query(
      "SELECT setting_key, setting_value FROM platform_settings WHERE setting_key IN ('commission_rate', 'oneway_hub_fee', 'doorstep_delivery_fee')"
    );
    const settings = Object.fromEntries(settingsRows.map((row) => [row.setting_key, Number(row.setting_value) || 0]));
    const commissionRate = Math.max(0, Math.min(100, settings.commission_rate ?? 12));
    const oneWayFee = settings.oneway_hub_fee ?? 450;
    const doorstepFee = settings.doorstep_delivery_fee ?? 199;
    const deliveryFee = pickupMode === "CITYFLEX_DELIVERY" ? doorstepFee : 0;
    let returnFee = 0;
    if (returnMode === "HUB_RETURN") returnFee = oneWayFee;
    else if (returnMode === "DOORSTEP_COLLECTION") returnFee = doorstepFee;
    const discountAmount = String(b.couponCode || "").trim().toUpperCase() === "FUELHUB50" ? 150 : 0;
    const taxableSubtotal = Math.max(0, calculatedRental + deliveryFee + returnFee - discountAmount);
    const gstTax = Math.round(taxableSubtotal * 0.18);
    const depositAmount = Math.max(0, Number(bookingVehicle.deposit) || 0);
    const trustedTotal = taxableSubtotal + gstTax + depositAmount;
    const platformCommission = Math.round(calculatedRental * (commissionRate / 100));
    const hostPayout = Math.max(0, calculatedRental - platformCommission);
    const id = `BK-${crypto.randomUUID()}`;
    const otp = crypto.randomInt(1000, 10000).toString();

    await pool.query(
      `INSERT INTO bookings (
        id, customer_user_id, owner_user_id, vehicleId, vehicleName,
        customerName, customerPhone, customerEmail, customerDl,
        plan, days, dates, pickupCity, pickupMode, deliveryAddress,
        returnMode, partnerName, deliveryStatus, bookingStatus, paymentStatus,
        rentalCharge, deliveryFee, returnFee, discountAmount, gstTax, depositAmount,
        quotedTotal, platformCommission, hostPayout, handoverOtp, createdAt
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)` ,
      [
        id,
        req.user.user_id,
        bookingVehicle.owner_user_id || null,
        bookingVehicle.id,
        bookingVehicle.name,
        String(b.customerName || bookingProfile.full_name || req.user.username).trim().slice(0, 255),
        String(b.customerPhone || bookingProfile.phone || "").trim().slice(0, 64),
        req.user.email,
        bookingProfile.driving_licence || "",
        String(b.plan || "Daily Drives").slice(0, 255),
        calculatedDays,
        String(b.dates || "").slice(0, 255),
        String(b.pickupCity || "Chandigarh").slice(0, 100),
        pickupMode,
        pickupMode === "CITYFLEX_DELIVERY" ? String(b.deliveryAddress || "").slice(0, 500) : "",
        returnMode,
        "Assigned Partner",
        "REQUEST RECEIVED",
        "PENDING",
        "NOT PROCESSED (Demo)",
        calculatedRental,
        deliveryFee,
        returnFee,
        discountAmount,
        gstTax,
        depositAmount,
        trustedTotal,
        platformCommission,
        hostPayout,
        otp,
        new Date().toISOString().split("T")[0]
      ]
    );

    const [[booking]] = await pool.query("SELECT * FROM bookings WHERE id = ?", [id]);
    res.status(201).json({ success: true, booking });
  } catch (err) {
    console.error("Create booking error:", err.message);
    res.status(500).json({ success: false, message: "Failed to save booking." });
  }
});

app.patch("/api/bookings/:id/extend", async (req, res) => {
  try {
    const { id } = req.params;
    const { extraDays = 1, incrementalAmount = 0 } = req.body || {};
    const [[existing]] = await pool.query("SELECT * FROM bookings WHERE id = ?", [id]);
    if (!existing) return res.status(404).json({ success: false, message: "Booking not found." });
    if (req.user.role !== "ADMIN" && existing.customer_user_id !== req.user.user_id) {
      return res.status(403).json({ success: false, message: "You can only extend your own booking." });
    }
    const safeExtraDays = Math.max(1, Math.min(30, Number(extraDays) || 1));
    const newTotal = Number(existing.quotedTotal) + Math.max(0, Number(incrementalAmount) || 0);
    const newDays = Math.min(120, Number(existing.days) + safeExtraDays);
    const newPlan = `${existing.plan} (+${safeExtraDays}d Extended)`;
    await pool.query(
      "UPDATE bookings SET days = ?, plan = ?, quotedTotal = ?, bookingStatus = 'EXTENDED & CONFIRMED' WHERE id = ?",
      [newDays, newPlan, newTotal, id]
    );
    const [[booking]] = await pool.query("SELECT * FROM bookings WHERE id = ?", [id]);
    res.json({ success: true, booking: req.user.role === "CUSTOMER" ? booking : hideHandoverOtp(booking) });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to extend booking." });
  }
});

app.patch("/api/bookings/:id/verify-otp", async (req, res) => {
  try {
    const { id } = req.params;
    const { handoverOtp = "", odometer = 0 } = req.body || {};
    const [[existing]] = await pool.query("SELECT * FROM bookings WHERE id = ?", [id]);
    if (!existing) return res.status(404).json({ success: false, message: "Booking not found." });
    if (req.user.role !== "ADMIN" && existing.owner_user_id !== req.user.user_id) {
      return res.status(403).json({ success: false, message: "You can only verify handover for vehicles you own." });
    }

    if (existing.bookingStatus === "ACTIVE_RENTAL") return res.status(409).json({ success: false, message: "Handover already verified." });
    if (!/^\d{4}$/.test(String(handoverOtp).trim()) || !Number.isFinite(Number(odometer)) || Number(odometer) < 0) {
      return res.status(400).json({ success: false, message: "Enter a valid OTP and odometer reading." });
    }
    if (!allowAttempt(otpAttempts, id, 5, 15 * 60 * 1000)) {
      return res.status(429).json({ success: false, message: "Too many OTP attempts. Try again in 15 minutes." });
    }
    if (String(existing.handoverOtp).trim() !== String(handoverOtp).trim()) {
      return res.status(400).json({ success: false, message: "Incorrect 4-digit Handover OTP." });
    }

    const [updated] = await pool.query(
      "UPDATE bookings SET bookingStatus = 'ACTIVE_RENTAL', deliveryStatus = 'HANDOVER VERIFIED / ON TRIP', startOdometer = ? WHERE id = ? AND bookingStatus <> 'ACTIVE_RENTAL'",
      [Number(odometer), id]
    );
    if (!updated.affectedRows) return res.status(409).json({ success: false, message: "Handover already verified." });
    otpAttempts.delete(id);
    const [[booking]] = await pool.query("SELECT * FROM bookings WHERE id = ?", [id]);
    res.json({ success: true, booking: hideHandoverOtp(booking) });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to verify OTP." });
  }
});

app.get("/api/driver-bookings", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT * FROM driver_requests ORDER BY createdAt DESC");
    res.json({ success: true, driverBookings: rows });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to fetch driver bookings." });
  }
});

app.post("/api/driver-bookings", async (req, res) => {
  try {
    const b = req.body || {};
    const [result] = await pool.query(
      `INSERT INTO driver_requests (
        customer_user_id, customerName, mode, city, servicePackage,
        vehicleClass, pickupLocation, destinationLocation, pickupDateTime,
        customerMobile, specialNotes, quotedTotal
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        req.user.user_id,
        (await getUserWithProfile(req.user.user_id))?.profile?.full_name || req.user.username,
        ["MODE_A", "MODE_B"].includes(b.mode) ? b.mode : "MODE_A",
        b.city || "Chandigarh",
        b.servicePackage || "8hr",
        b.vehicleClass || null,
        b.pickupLocation || "",
        b.destinationLocation || "",
        b.pickupDateTime || "",
        b.customerMobile || "",
        b.specialNotes || "",
        Number(b.quotedTotal) || 0
      ]
    );
    const [[driverBooking]] = await pool.query("SELECT * FROM driver_requests WHERE id = ?", [result.insertId]);
    res.status(201).json({ success: true, driverBooking });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to save driver booking." });
  }
});

app.use("/api", (req, res) => {
  res.status(404).json({ success: false, message: "API endpoint not found." });
});

function removeDashboardTemplate(html, templateId) {
  const openRegex = new RegExp(`<template\\b(?=[^>]*\\bid=["']${templateId}["'])[^>]*>`, "i");
  const match = openRegex.exec(html);
  if (!match) return html;
  const start = match.index;
  let cursor = start + match[0].length;
  let depth = 1;
  const tagRegex = /<\/?template\b[^>]*>/ig;
  tagRegex.lastIndex = cursor;
  let tag;
  while ((tag = tagRegex.exec(html))) {
    if (/^<\s*\/template/i.test(tag[0])) depth -= 1;
    else depth += 1;
    if (depth === 0) return html.slice(0, start) + html.slice(tag.index + tag[0].length);
  }
  return html;
}

function sendFrontend(req, res) {
  try {
    let html = fs.readFileSync(path.join(__dirname, "index.html"), "utf8");
    const allowedTemplateByRole = {
      CUSTOMER: "tpl-customer_dashboard",
      OWNER: "tpl-owner_dashboard",
      ADMIN: "tpl-admin_dashboard"
    };
    const allowedTemplate = req.user ? allowedTemplateByRole[req.user.role] : null;
    for (const templateId of Object.values(allowedTemplateByRole)) {
      if (templateId !== allowedTemplate) html = removeDashboardTemplate(html, templateId);
    }
    const loginPortalByPath = {
      "/customer-login.html": "CUSTOMER",
      "/owner-login.html": "OWNER",
      "/admin-login.html": "ADMIN"
    };
    const loginRole = loginPortalByPath[req.path];
    if (loginRole) {
      const portalScript = `<script>(function(){const role=${JSON.stringify(loginRole)};const selector=document.getElementById("login-role");if(selector){if(!Array.from(selector.options).some(o=>o.value===role)){const option=document.createElement("option");option.value=role;option.textContent=role==="ADMIN"?"Administrator":"Vehicle Owner";selector.appendChild(option);}selector.value=role;selector.disabled=true;}if(typeof openAuthModal==="function")openAuthModal("LOGIN",role);})();</script>`;
      html = html.replace("</body>", `${portalScript}</body>`);
    }
    res.setHeader("Cache-Control", "no-store, private");
    res.type("html").send(html);
  } catch (err) {
    console.error("Frontend delivery error:", err.message);
    res.status(500).send("CityFlex could not load. Please restart the server.");
  }
}

app.get(["/", "/index.html"], sendFrontend);
// Hash-based SPA routes use the same entry point; private dashboard markup is role-filtered server-side.
app.get(/^\/(?!api\/).*/, sendFrontend);

initDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`CityFlex Rentals server running at http://localhost:${PORT}`);
      console.log(`Connected to MySQL database: ${DB_NAME}`);
    });
  })
  .catch((err) => {
    console.error("Failed to initialize MySQL database:", err.message);
    process.exit(1);
  });
