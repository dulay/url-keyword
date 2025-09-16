import pandas as pd
import os

def init_tasks():
    if not os.path.exists("tasks.csv"):
        df = pd.DataFrame(columns=['id', 'user', 'name', 'time', 'status', 'filename', 'progress'])
        df.to_csv("tasks.csv", index=False)
        print("tasks.csv 初始化完成")

def init_users():
    if not os.path.exists("users.csv"):
        df = pd.DataFrame(columns=['name', 'password_hash', 'approved', 'is_admin'])
        df.to_csv("users.csv", index=False)
        print("users.csv 初始化完成")

if __name__ == "__main__":
    init_tasks()
    init_users()