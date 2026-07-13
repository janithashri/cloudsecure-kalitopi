mods = ["networkx", "numpy", "scipy", "sklearn", "gensim", "matplotlib", "tqdm", "pandas"]
missing = []
for mod in mods:
    try:
        __import__(mod)
        print(f"{mod}: OK")
    except ImportError as exc:
        print(f"{mod}: MISSING ({exc})")
        missing.append(mod)
print("MISSING_LIST:", ",".join(missing))
