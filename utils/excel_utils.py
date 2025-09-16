import pandas as pd

TEMPLATE_COLUMNS = ['序号', 'URL', '关键词']

def create_template(file_path):
    df = pd.DataFrame(columns=TEMPLATE_COLUMNS)
    df.to_excel(file_path, index=False)

def read_excel(file_path):
    return pd.read_excel(file_path)

def write_excel(df, file_path):
    df.to_excel(file_path, index=False)