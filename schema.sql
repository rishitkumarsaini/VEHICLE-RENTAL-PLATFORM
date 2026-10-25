-- ============================================================================
-- CityFlex Rentals — Normalized Multi-Role MySQL Database Schema (PRD v1.1)
-- Separates Users, Role-Specific Profiles (Customer, Owner, Admin),
-- Vehicles (Platform & Personal Host), Sale Listings, Bookings,
-- Driver Requests, Buyer Inquiries, and Platform Settings into distinct tables.
-- ============================================================================

CREATE DATABASE IF NOT EXISTS cityflex_db
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE cityflex_db;

-- ----------------------------------------------------------------------------
-- 1. USERS TABLE (Authentication & Login Credentials for All Roles)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  user_id VARCHAR(64) PRIMARY KEY,
  role ENUM('CUSTOMER', 'OWNER', 'ADMIN') NOT NULL,
  username VARCHAR(100) NOT NULL UNIQUE,
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ----------------------------------------------------------------------------
-- 2. CUSTOMER PROFILES TABLE (Personal Data & DL for Vehicle Renters)
-- ----------------------------------------------------------------------------
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
) ENGINE=InnoDB;

-- ----------------------------------------------------------------------------
-- 3. OWNER PROFILES TABLE (Host / Garage Data for Personal Vehicle Owners)
-- ----------------------------------------------------------------------------
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
) ENGINE=InnoDB;

-- ----------------------------------------------------------------------------
-- 4. ADMIN PROFILES TABLE (Administrator Identity & Cluster Assignment)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin_profiles (
  user_id VARCHAR(64) PRIMARY KEY,
  admin_name VARCHAR(255) NOT NULL DEFAULT '',
  designation VARCHAR(150) NOT NULL DEFAULT 'Platform Administrator',
  phone VARCHAR(64) NOT NULL DEFAULT '',
  operating_cluster VARCHAR(150) NOT NULL DEFAULT 'Punjab & Chandigarh/Tricity',
  employee_code VARCHAR(64) NOT NULL DEFAULT 'ADM-001',
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_admin_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ----------------------------------------------------------------------------
-- 5. VEHICLES TABLE (Fleet & Personal Owner Rental Vehicles)
-- ----------------------------------------------------------------------------
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
) ENGINE=InnoDB;

-- ----------------------------------------------------------------------------
-- 6. SALE LISTINGS TABLE (Personal Vehicles Listed for Permanent Sale)
-- ----------------------------------------------------------------------------
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
) ENGINE=InnoDB;

-- ----------------------------------------------------------------------------
-- 7. BOOKINGS TABLE (Vehicle Rental Reservations & Commission Breakdown)
-- ----------------------------------------------------------------------------
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
  recordedAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_booking_customer FOREIGN KEY (customer_user_id) REFERENCES users(user_id) ON DELETE SET NULL,
  CONSTRAINT fk_booking_vehicle FOREIGN KEY (vehicleId) REFERENCES vehicles(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ----------------------------------------------------------------------------
-- 8. DRIVER REQUESTS TABLE (Rent-a-Driver Mode A & Mode B Bookings)
-- ----------------------------------------------------------------------------
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
  createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_driver_customer FOREIGN KEY (customer_user_id) REFERENCES users(user_id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ----------------------------------------------------------------------------
-- 9. BUYER INQUIRIES TABLE (Marketplace Buy/Sell Viewing Requests)
-- ----------------------------------------------------------------------------
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
) ENGINE=InnoDB;

-- ----------------------------------------------------------------------------
-- 10. PLATFORM SETTINGS TABLE (Configurable Commission & Operational Fees)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS platform_settings (
  setting_key VARCHAR(64) PRIMARY KEY,
  setting_value VARCHAR(255) NOT NULL,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- No demo users or plaintext passwords are seeded. The server bootstraps one
-- administrator account with a generated password or ADMIN_PASSWORD from .env.
INSERT IGNORE INTO platform_settings (setting_key, setting_value) VALUES
  ('commission_rate', '12'),
  ('oneway_hub_fee', '450'),
  ('doorstep_delivery_fee', '199');
