import pytest
import detector

# ----------- Test search SQLi payloads ----------

@pytest.mark.parametrize("payload", [
# Tautology
    "' UNION SELECT * FROM users WHERE username='admin' or '1'='1'--",
    "' UNION SELECT * FROM users WHERE username='admin' OR '1'='1'--",
    "' UNION SELECT * FROM users WHERE username='admin' OR ''=''--",
    "' UNION SELECT * FROM users WHERE username='admin' OR TRUE--",
    "' UNION SELECT * FROM users WHERE username='admin' OR 'a'='a'--",
    "' UNION SELECT * FROM users WHERE username='admin' OR 0x31=0x31--",
    "' UNION SELECT * FROM users WHERE username='admin' or (1=1)--",
    "' UNION SELECT * FROM users WHERE username='admin' or ((1=1))--",
    "' UNION SELECT * FROM users WHERE username='admin' or ('a'='a')--",
    "' UNION SELECT * FROM users WHERE username='admin' or ('1'='1')--",
    "' UNION SELECT * FROM users WHERE username='admin' or (''='')--",
    "' UNION SELECT * FROM users WHERE username='admin' or (0x31=0x31)--",
    "' UNION SELECT * FROM users WHERE username='admin' or (1 like 1)--",
    "' UNION SELECT * FROM users WHERE username='admin' or (1 regexp 1)--",

    "' UNION SELECT * FROM users WHERE username='admin' or (if(1=1,1,0))--",
    "' UNION SELECT * FROM users WHERE username='admin' or coalesce(NULL,1)--",
    "' UNION SELECT * FROM users WHERE username='admin' or (1 BETWEEN 1 AND 1)--",
    "' UNION SELECT * FROM users WHERE username='admin' or true--",
    "' UNION SELECT * FROM users WHERE username='admin' or false or '1'='1'--",
    "' UNION SELECT * FROM users WHERE username='admin' or (LENGTH('abc')=3)--",
    "' UNION SELECT * FROM users WHERE username='admin' or (SELECT MIN(id) FROM users)<9999--",
    "' UNION SELECT * FROM users WHERE username='admin' or EXISTS(SELECT * FROM product)--",
    "' UNION SELECT * FROM users WHERE username='admin' or (SELECT 1)--",
    "' UNION SELECT * FROM users WHERE username='admin' or ascii(substring((select user()),1,1))>64--",
    "' UNION SELECT * FROM users WHERE username='admin' or (SELECT COUNT(*) FROM users)>0--",
    "' UNION SELECT * FROM users WHERE username='admin' or (SELECT SLEEP(0)=0)--",
    "' UNION SELECT * FROM users WHERE username='admin' or (SELECT database())='myDB'--",
    "' UNION SELECT * FROM users WHERE username='admin' or (SELECT IF(1=1,1,0))--",
    "' UNION SELECT * FROM users WHERE username='admin' or (SELECT CASE WHEN 1=1 THEN 1 ELSE 0 END)--",

# UNION-based
    "' UNION SELECT 1, 'hacked', 999, 1.11--",
    "' UNION SELECT id, name_product, quantity, price FROM product --",
    "' UNION SELECT 1,2,3,4 --",
    "' UNION SELECT null, null, null, null --",
    "' UNION SELECT id, password, email, null FROM users--",
    "' UNION SELECT id, username, password, null FROM users--",
    "' UNION SELECT id, name_product, quantity, price FROM product--",
    "' UNION SELECT id, username, NULL, NULL FROM users--",
    "' UNION SELECT id, 'constant', 123, 4.5 FROM users--",
    "' UNION SELECT null, null, null, null--",
    "' UNION SELECT version(), user(), database(), 1--",
    "' UNION SELECT 1,2,3,4--",
    "' UNION ALL SELECT 1, 'x', 2, 3.3--",
    "' UNION SELECT id, username, password, email FROM users WHERE 'a'='a'--",
    "' UNION SELECT id, name_product, quantity, price FROM product WHERE 1=1--",

    "' UNION SELECT id, username, password, email FROM users WHERE id=(SELECT MIN(id) FROM users)--",
    "' UNION SELECT COUNT(*), MAX(id), MIN(id), AVG(id) FROM users--",
    "' UNION SELECT id, name_product, quantity, price FROM product WHERE price>(SELECT AVG(price) FROM product)--",
    "' UNION SELECT version(), user(), database(), @@datadir--",
    "' UNION SELECT 1, 2, user(), database() FROM dual--",
    "' UNION SELECT IF(1=1, id, NULL), username, password, email FROM users--",
    "' UNION SELECT id, (SELECT password FROM users WHERE username='admin'), 1, 1 FROM users--",
    "' UNION SELECT table_name, column_name, 1, 1 FROM information_schema.columns WHERE table_schema=database()--",
    "' union select @@version, @@hostname, 1, 2--",
    "' union select md5(123), sha1('abc'), now(), user()--",
    "' union all select 1, group_concat(username), null, null from users--",
    "' union select load_file('/etc/passwd'), null, null, null--",

# Error-based
    "' AND updatexml(1,concat(0x7e,(select database())),0)--",
    "' AND 1/0 --",
    "' AND extractvalue(1,concat(0x7e,(select user())),0)--",
    "' AND updatexml(1,concat(0x7e,(select user())),0)--",
    "' AND updatexml(1,concat(0x7e,(select database())),0)--",
    "' AND extractvalue(1,concat(0x7e,(select database())),0)--",
    "' AND extractvalue(1,concat(0x7e,(select version())),0)--",
    "' AND cast('abc' AS DECIMAL)--",
    "' AND convert('abc', DECIMAL)--",
    "' AND 1/0--",
    "' AND (select 1/0 from dual)--",
    "' AND char(99999999999)--",
    "' AND exp(~(SELECT * FROM (SELECT USER())a))--",
    "' AND updatexml(1,concat(0x7e,(select user())),0)--",        # updatexml
    "' AND exp(~(SELECT * FROM (SELECT USER())a))--",             # exp + subquery
    "' AND JSON_KEYS('abc')--",                                   # function json_keys
    "' AND uuid_to_bin('abc')--",                                 # uuid_to_bin
    "' AND GTID_SUBSET('abc',123)--",                             # GTID_SUBSET lỗi
    "' AND NAME_CONST(version(),1)--",                            # name_const
    "' AND CONVERT('abc', DECIMAL)--",                            # convert lỗi kiểu dữ liệu
    "' AND UPDATEXML(NULL, CONCAT(0x3a, (SELECT version())), NULL)--", # updatexml error khác
    "' AND updatexml(1,concat(0x7e,(select database())),0) --",

    "' AND (SELECT 1/0 FROM dual)--",
    "' AND (SELECT updatexml(1,concat(0x7e,(SELECT user())),0))--",
    "' AND IF((SELECT COUNT(*) FROM users)>0, updatexml(1,concat(0x7e,user()),0), 0)--",
    "' AND IF(1=1, CAST('abc' AS DECIMAL), 1)--",
    "' AND (SELECT CAST('abc' AS DECIMAL) FROM dual)--",
    "' AND (SELECT exp(~(SELECT * FROM (SELECT user())a)))--",
    "' AND (SELECT 1/0 UNION SELECT 2/0)--",
    "' AND IFNULL(NULL, updatexml(1,concat(0x7e,user()),0))--",
    "' AND (SELECT CONVERT('abc', DECIMAL))--",
    "' AND (SELECT UPDATEXML(NULL, CONCAT(0x3a, (SELECT version())), NULL))--",

# Time-based
    "' AND SLEEP(5)--",
    "' OR SLEEP(5)--",
    "' AND BENCHMARK(1000000,MD5(1))--",
    "' AND IF(1=1,SLEEP(3),0)--",
    "' OR IF(1=1,BENCHMARK(1000000,MD5(1)),0)--",
    "' AND IFNULL(NULL,SLEEP(2))--",
    "' AND SLEEP(2)--",                                 # sleep nhỏ
    "' AND SLEEP(10)--",                                # sleep lớn
    "' OR SLEEP(5)--",                                  # sleep OR
    "' AND BENCHMARK(1000000,MD5(1))--",                # benchmark
    "' AND IF(1=1,SLEEP(3),0)--",                       # lồng IF SLEEP
    "' AND IFNULL(NULL,SLEEP(2))--",                    # function ifnull sleep
    "' AND SLEEP(1+1)--",                               # sleep toán tử
    "' AND IF(EXISTS(SELECT * FROM users),SLEEP(3),0)--", # exists + sleep
    "' AND (SELECT IF(1=1,SLEEP(3),0))--",              # select if
    "' AND 1=1 AND SLEEP(3)--",                         # double logic

    "' AND IF(EXISTS(SELECT * FROM users WHERE username='admin'), SLEEP(2), 0)--",
    "' AND IF((SELECT COUNT(*) FROM product)>0, SLEEP(3), 0)--",
    "' AND IFNULL(NULL, SLEEP(2))--",
    "' AND (SELECT SLEEP(5) FROM dual WHERE 1=1)--",
    "' AND (SELECT IF(1=1,SLEEP(2),0))--",
    "' AND IF(ASCII(SUBSTRING((SELECT user()),1,1))>64, SLEEP(2), 0)--",
    "' AND IF(1=1,BENCHMARK(1000000,MD5('test')),0)--",
    "' AND BENCHMARK(1000000,MD5((SELECT user())))--",
    "' OR (SELECT SLEEP(2) WHERE (SELECT COUNT(*) FROM users)>0)--",
    "' AND SLEEP(3-1)--",

# Stacked queries
    "\" OR 1=1; DROP TABLE users;--",
    "admin\" or 1=1; SHUTDOWN --",
    "' SELECT * FROM product; UPDATE product SET price=1 WHERE id=1; --",
    "' SELECT * FROM product; UPDATE product SET price=1 WHERE quantity=10; --",
    "\" OR 1=1; SELECT * FROM users; --",
    "\" OR 1=1; SELECT * FROM product; --",
    "'; SELECT * FROM product WHERE price=28990.00;--",
    "'; INSERT INTO product (name_product,quantity,price) VALUES ('hacked',99,0); --",
    "'; DROP TABLE IF EXISTS users;--",
    "'; ALTER TABLE users ADD COLUMN hack INT;--",
    "'; TRUNCATE TABLE product;--",
    "'; SELECT * FROM users WHERE username='admin';--",
    "'; GRANT ALL PRIVILEGES ON *.* TO 'hacker'@'%';--",              
    "'; CREATE USER 'test'@'%' IDENTIFIED BY '123';--", 
    "'; ROLLBACK; --",

    "'; COMMIT; --",
    "'; ROLLBACK; --",
    "'; DELETE FROM product WHERE price=28990.00; --",
    "'; ALTER TABLE product ADD COLUMN hack INT; --",
    "'; INSERT INTO users (username,password,email) VALUES ('attacker','test','a@a.com'); --",
    "'; DROP TABLE IF EXISTS product; --",
    "'; REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'admin'@'%'; --",
    "'; FLUSH PRIVILEGES; --",
    "'; CREATE TEMPORARY TABLE hacked AS SELECT * FROM users; --",
    "'; TRUNCATE TABLE users; --",
    "'; LOAD DATA INFILE '/etc/passwd' INTO TABLE product FIELDS TERMINATED BY ':'; --",

])
def test_search_payloads(monkeypatch, payload):
    # Giả lập chèn vào query
    query = f"SELECT * FROM product WHERE name_product LIKE '%{payload}%'"
    # Tránh ghi log khi test
    monkeypatch.setattr(detector, "write_attack_log", lambda q, t: None)
    assert detector.check_exploit_sqli(query)

# ----------- Negative test (not detected as SQLi) ----------
@pytest.mark.parametrize("payload", [
    "iPhone",
    "MacBook",
    "Ultra",
    "Pro Max 128GB",
    "Samsung Galaxy S23",
    "Laptop Dell"
])
def test_search_non_sqli_payloads(monkeypatch, payload):
    query = f"SELECT * FROM product WHERE name_product LIKE '%{payload}%'"
    monkeypatch.setattr(detector, "write_attack_log", lambda q, t: None)
    assert not detector.check_exploit_sqli(query)
