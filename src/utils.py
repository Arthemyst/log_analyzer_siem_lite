def load_log_file(path):
    with open(path, "r") as f:
        return f.readlines()
