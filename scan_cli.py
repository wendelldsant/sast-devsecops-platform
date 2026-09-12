from app.engine.parser import scan_file

if __name__ == "__main__":
    results = scan_file("tests/vulnerable_sample.py")
    for r in results:
        print(r)