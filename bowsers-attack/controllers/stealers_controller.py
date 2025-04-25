from dumpers import browser_dump, redline_clone

def run_all():
    print("Executando browser_dump...")
    browser_dump.main()

    print("Executando redline_clone...")
    redline_clone.main()

if __name__ == "__main__":
    run_all()
