-- ============================================================
-- ECWF Shared MySQL Server - Database Initialization
-- Runs once when the mysql container is first created.
-- Creates all ECWF databases and application users on a
-- single MySQL server instance.
-- Tables are created by each service on startup (create_all).
-- ============================================================

-- Auth database + user
CREATE DATABASE IF NOT EXISTS ecwf_auth_db;
CREATE USER IF NOT EXISTS 'auth_user'@'%' IDENTIFIED BY 'auth_password';
GRANT ALL PRIVILEGES ON ecwf_auth_db.* TO 'auth_user'@'%';

-- Tenant database + user
CREATE DATABASE IF NOT EXISTS ecwf_tenant_db;
CREATE USER IF NOT EXISTS 'tenant_user'@'%' IDENTIFIED BY 'tenant_password';
GRANT ALL PRIVILEGES ON ecwf_tenant_db.* TO 'tenant_user'@'%';

-- Notification database + user
CREATE DATABASE IF NOT EXISTS ecwf_notification_db;
CREATE USER IF NOT EXISTS 'notification_user'@'%' IDENTIFIED BY 'notification_password';
GRANT ALL PRIVILEGES ON ecwf_notification_db.* TO 'notification_user'@'%';

FLUSH PRIVILEGES;