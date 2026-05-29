with open("switchy.txt", encoding="utf-8") as f:
    lines = sorted(set(f))
with open("switchy.txt", "w", encoding="utf-8", newline="\n") as f:
    for l in lines:
        f.write(l)
        if not l.endswith("\n"):
            f.write("\n")
