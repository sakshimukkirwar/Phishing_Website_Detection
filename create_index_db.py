import os
import sqlite3
import sqlparse

data_basepath = './n96ncsr5g4-1'
table_path = os.path.join(data_basepath, 'table.sql')
index_path = os.path.join(data_basepath, 'index.sql')
db_path = './phishing_index_db'

if os.path.exists(db_path) is True:
    os.remove(db_path)

conn = sqlite3.connect(db_path)
cursor = conn.cursor()
with open(table_path, 'r') as file:
    sql_script = file.read()
cursor.executescript(sql_script)

with open(index_path, 'r') as file:
    sql_script = file.read()

parsed_script = sqlparse.split(sql_script)
insert_statements = [stmt for stmt in parsed_script if 'INSERT' in stmt.upper()]

for i, insert_statement in enumerate(insert_statements):
    cursor.executescript(insert_statement)

conn.commit()
conn.close()
print(f'{db_path} created')