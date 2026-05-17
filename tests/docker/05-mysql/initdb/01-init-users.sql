-- Create users for brute-force validation

CREATE USER IF NOT EXISTS 'test'@'%' IDENTIFIED WITH mysql_native_password BY 'testpass1';
CREATE USER IF NOT EXISTS 'admin'@'%' IDENTIFIED WITH mysql_native_password BY 'admin123';
CREATE USER IF NOT EXISTS 'query'@'%' IDENTIFIED WITH mysql_native_password BY 'query_query';

GRANT ALL PRIVILEGES ON brutedb.* TO 'test'@'%';
GRANT ALL PRIVILEGES ON brutedb.* TO 'admin'@'%';
GRANT SELECT ON brutedb.* TO 'query'@'%';

CREATE TABLE IF NOT EXISTS brutedb.login_probe (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(64) NOT NULL,
    note VARCHAR(128) NOT NULL
);

INSERT INTO brutedb.login_probe (username, note)
VALUES
    ('test', 'mysql brute validation account'),
    ('admin', 'mysql brute validation account'),
    ('query', 'mysql brute validation account');

FLUSH PRIVILEGES;
