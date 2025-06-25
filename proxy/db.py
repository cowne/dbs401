import mysql.connector
from mysql.connector import Error
import os

def get_connection():
    return mysql.connector.connect(
        host='db',
        user='db_user',
        password='db_password',
        database='myDB',
        port = 3306,
        ssl_ca="/app/certs/ca.pem",
        ssl_cert="/app/certs/client-cert.pem",
        ssl_key="/app/certs/client-key.pem",
        ssl_verify_cert=True
    )

def run_query(sql, params=None):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    sql=sql.lower()
    cursor.execute(sql, params or ())
    
    if sql.strip().startswith("select"):
        result = cursor.fetchall()
    else:
        conn.commit()
        result = None

    cursor.close()
    conn.close()
    return result