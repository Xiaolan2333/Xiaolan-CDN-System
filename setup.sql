CREATE DATABASE IF NOT EXISTS `xiaolan-cdn` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE `xiaolan-cdn`;

-- SSL certificates
CREATE TABLE IF NOT EXISTS ssl_certificates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    private_key TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Lua scripts
CREATE TABLE IF NOT EXISTS lua_scripts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    content TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Nodes
CREATE TABLE IF NOT EXISTS nodes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    host VARCHAR(255) NOT NULL,
    port INT NOT NULL DEFAULT 22,
    username VARCHAR(255) NOT NULL DEFAULT 'root',
    password VARCHAR(255) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Sites
CREATE TABLE IF NOT EXISTS sites (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    origin_scheme VARCHAR(10) NOT NULL DEFAULT 'http',
    origin_address VARCHAR(500) NOT NULL,
    origin_host VARCHAR(255) NOT NULL DEFAULT '',
    https_enabled TINYINT(1) NOT NULL DEFAULT 0,
    ssl_certificate_id INT DEFAULT NULL,
    hsts_enabled TINYINT(1) NOT NULL DEFAULT 0,
    tls_versions VARCHAR(100) NOT NULL DEFAULT 'TLSv1.2 TLSv1.3',
    http2_enabled TINYINT(1) NOT NULL DEFAULT 1,
    http3_enabled TINYINT(1) NOT NULL DEFAULT 0,
    websocket_enabled TINYINT(1) NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (ssl_certificate_id) REFERENCES ssl_certificates(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Site domains
CREATE TABLE IF NOT EXISTS site_domains (
    id INT AUTO_INCREMENT PRIMARY KEY,
    site_id INT NOT NULL,
    domain VARCHAR(255) NOT NULL,
    UNIQUE KEY unique_domain (domain),
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Redirect rules (301/302)
CREATE TABLE IF NOT EXISTS redirect_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    site_id INT NOT NULL,
    from_path VARCHAR(500) NOT NULL,
    to_url VARCHAR(1000) NOT NULL,
    redirect_type INT NOT NULL DEFAULT 301,
    sort_order INT NOT NULL DEFAULT 0,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Cache rules
CREATE TABLE IF NOT EXISTS cache_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    site_id INT NOT NULL,
    suffix VARCHAR(50) NOT NULL,
    cache_time VARCHAR(20) NOT NULL DEFAULT '30d',
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Path-based origin rules
CREATE TABLE IF NOT EXISTS path_origin_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    site_id INT NOT NULL,
    path_pattern VARCHAR(500) NOT NULL,
    origin_scheme VARCHAR(10) NOT NULL DEFAULT 'http',
    origin_address VARCHAR(500) NOT NULL,
    origin_host VARCHAR(255) NOT NULL DEFAULT '',
    lua_script_id INT DEFAULT NULL,
    sort_order INT NOT NULL DEFAULT 0,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Site Lua script bindings
CREATE TABLE IF NOT EXISTS site_lua_bindings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    site_id INT NOT NULL,
    lua_script_id INT NOT NULL,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE,
    FOREIGN KEY (lua_script_id) REFERENCES lua_scripts(id) ON DELETE CASCADE,
    UNIQUE KEY unique_binding (site_id, lua_script_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- IP blacklist
CREATE TABLE IF NOT EXISTS site_ip_blacklist (
    id INT AUTO_INCREMENT PRIMARY KEY,
    site_id INT NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    UNIQUE KEY unique_ip (site_id, ip_address),
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Access logs
CREATE TABLE IF NOT EXISTS access_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    node_id INT NOT NULL,
    site_id INT DEFAULT NULL,
    status_code INT NOT NULL,
    domain VARCHAR(255) NOT NULL DEFAULT '',
    request_path VARCHAR(2000) NOT NULL DEFAULT '',
    client_ip VARCHAR(45) NOT NULL DEFAULT '',
    request_time DATETIME NOT NULL,
    cookie TEXT,
    user_agent TEXT,
    bytes_sent BIGINT NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_request_time (request_time),
    INDEX idx_domain (domain),
    INDEX idx_status_code (status_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- System logs
CREATE TABLE IF NOT EXISTS system_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    level VARCHAR(20) NOT NULL DEFAULT 'INFO',
    category VARCHAR(50) NOT NULL DEFAULT 'system',
    message TEXT NOT NULL,
    detail TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_created_at (created_at),
    INDEX idx_level (level)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
