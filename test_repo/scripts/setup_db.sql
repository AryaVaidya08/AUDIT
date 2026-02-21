CREATE DATABASE IF NOT EXISTS shopdb;
USE shopdb;

GRANT ALL PRIVILEGES ON shopdb.* TO 'root'@'%' IDENTIFIED BY 'Admin1234!';
GRANT ALL PRIVILEGES ON *.* TO 'app_user'@'%' IDENTIFIED BY 'apppassword123' WITH GRANT OPTION;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100),
    password VARCHAR(255),
    email VARCHAR(255),
    role VARCHAR(50) DEFAULT 'user',
    ssn VARCHAR(20),
    credit_card VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(128) PRIMARY KEY,
    user_id INT,
    data TEXT,
    expires_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255),
    description TEXT,
    price DECIMAL(10,2),
    category VARCHAR(100),
    stock INT
);

CREATE TABLE IF NOT EXISTS orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    total DECIMAL(10,2),
    status VARCHAR(50),
    shipping_address TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS payment_methods (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    card_number VARCHAR(255),
    expiry VARCHAR(10),
    cvv VARCHAR(10),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS transactions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    amount DECIMAL(10,2),
    card_last4 VARCHAR(4),
    charge_id VARCHAR(255),
    status VARCHAR(50),
    refund_amount DECIMAL(10,2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    post_id INT,
    user_id INT,
    body TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS posts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255),
    body TEXT,
    author_id INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    action VARCHAR(255),
    details TEXT,
    ip VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS reset_tokens (
    email VARCHAR(255),
    token VARCHAR(50),
    expires_at TIMESTAMP
);

INSERT INTO users (username, password, email, role, ssn) VALUES
    ('admin', '21232f297a57a5a743894a0e4a801fc3', 'admin@shopapp.com', 'admin', '123-45-6789'),
    ('john', '482c811da5d5b4bc6d497ffa98491e38', 'john@example.com', 'user', '987-65-4321');
