import sqlite3
import time


class UsersDatabase:
    """Creates database with users table includes:
       create query
       insert query
       select query
    """

    def __init__(self, db_name="data_base"):
        conn = sqlite3.connect(f'{db_name}.db')
        query_str = "CREATE TABLE IF NOT EXISTS users ("
        query_str += "userid INTEGER PRIMARY KEY AUTOINCREMENT ,"
        query_str += "username TEXT NOT NULL ,"
        query_str += "password TEXT NOT NULL ,"
        query_str += "birthday datetime NOT NULL,"
        query_str += "email TEXT NOT NULL, "
        query_str += "is_logged_in BOOLEAN);"

        conn.execute(query_str)
        conn.commit()
        conn.close()
        self.__db_name = db_name

    def __str__(self):
        return "table name is users"

    def insert_user(self, username, password, birthday, email):
        conn = sqlite3.connect(f'{self.__db_name}.db')
        insert_query = "INSERT INTO users (username, password, birthday, email, is_logged_in) VALUES ( ?, ?, ?, ?, " \
                       "TRUE); "
        conn.execute(insert_query, (username, password, birthday, email,))
        conn.commit()
        conn.close()

    def del_user(self, user_database_id):
        conn = sqlite3.connect(f'{self.__db_name}.db')
        delete_query = "DELETE FROM users WHERE userid = ?;"
        conn.execute(delete_query, (user_database_id,))
        conn.commit()
        conn.close()

    def change_user(self, user_database_id, username=None, password=None, birthday=None, email=None):

        if not (username and password and birthday and email):
            return

        conn = sqlite3.connect(f'{self.__db_name}.db')

        # change_query = 'UPDATE users SET username = ?, password = ? WHERE userid = ?;'
        values = []
        change_query = "UPDATE users SET "
        change_list = []
        if username:
            change_list.append("username = ? ")
            values.append(username)

        if password:
            change_list.append(" password = ? ")
            values.append(password)

        if birthday:
            change_list.append(" birthday = ? ")
            values.append(birthday)

        if email:
            change_list.append(" email = ? ")
            values.append(email)
        values.append(user_database_id)
        change_query += ",".join(change_list)
        change_query += " WHERE userid = ?;"
        conn.execute(change_query, tuple(values))
        conn.commit()
        conn.close()

    def does_user_exist(self, username):
        conn = sqlite3.connect(f'{self.__db_name}.db')
        select_query = "SELECT * from users where username = ?"
        c = conn.execute(select_query, (username,))
        result = c.fetchone()
        conn.close()
        return not not result

    def does_email_exist(self, email):
        conn = sqlite3.connect(f'{self.__db_name}.db')
        select_query = "SELECT * from users where email = ?"
        c = conn.execute(select_query, (email,))
        result = c.fetchone()
        conn.close()
        return not not result

    def password_check(self, username, password):
        conn = sqlite3.connect(f'{self.__db_name}.db')
        select_query = "SELECT userid FROM users WHERE username = ? AND password = ?"
        c = conn.execute(select_query, (username, password))
        result = c.fetchone()
        conn.close()
        time.sleep(1)
        if result:
            return result[0]
        return None

    def is_user_logged_in(self, username):
        conn = sqlite3.connect(f'{self.__db_name}.db')
        select_query = "SELECT is_logged_in FROM users WHERE username = ?;"
        c = conn.execute(select_query, (username,))
        result = c.fetchone()
        conn.close()
        if result:
            return not not (result[0])
        return False

    def select_user_by_id(self, user_database_id):
        conn = sqlite3.connect(f'{self.__db_name}.db')
        select_query = "SELECT username, password from users where userid = ?"
        c = conn.execute(select_query, (user_database_id,))
        result = c.fetchone()
        conn.close()
        return result

    def get_user_id(self, username):
        conn = sqlite3.connect(f'{self.__db_name}.db')
        select_query = "SELECT userid FROM users WHERE username = ?;"
        c = conn.execute(select_query, (username,))
        result = c.fetchone()
        conn.close()
        time.sleep(1)
        if result:
            return result[0]
        return None

    def select_all_users(self):
        conn = sqlite3.connect(f'{self.__db_name}.db')
        select_query = f"SELECT * from users"
        c = conn.execute(select_query)
        result = c.fetchall()
        conn.close()
        return result


if __name__ == "__main__":
    u = UsersDatabase("userdata")
    user_id = u.password_check("idodon", "")
    print(user_id)
