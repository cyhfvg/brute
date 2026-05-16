-- Create users for brute-force validation

CREATE ROLE test LOGIN PASSWORD 'testpass1';
CREATE ROLE root LOGIN PASSWORD 'toor';
CREATE ROLE admin LOGIN PASSWORD 'admin123';
CREATE ROLE query LOGIN PASSWORD 'query_query';

-- Optional database permissions
ALTER ROLE test CREATEDB;
ALTER ROLE admin CREATEDB;

-- Create test database ownership
CREATE DATABASE brutedb OWNER test;
