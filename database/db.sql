create database if not exists myDB;

use myDB;

drop table if exists `users`;

CREATE TABLE IF NOT EXISTS users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100)
);

INSERT INTO users (username, password, email) VALUES
('admin', 'password123', 'admin@gmail.com'),
('minhtran', 'Minh@1234', 'minh.tran@gmail.com'),
('hoangnguyen', 'Hoang2024!', 'hoang.nguyen@yahoo.com'),
('linhpham', 'Linh#Pass01', 'linh.pham@hotmail.com'),
('anhtuan', 'Tuan!7890', 'anh.tuan@outlook.com');

drop table if exists `product`;

CREATE TABLE IF NOT EXISTS product (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name_product VARCHAR(100) NOT NULL,
    quantity INT DEFAULT 0,
    price DECIMAL(10, 2) NOT NULL
);

INSERT INTO product (name_product, quantity, price) VALUES
('iPhone 14 Pro Max 128GB', 10, 29990.00),
('Samsung Galaxy S23 Ultra', 8, 24990.00),
('MacBook Air M2 2023', 5, 28990.00),
('Laptop Dell XPS 13', 7, 25990.00);
