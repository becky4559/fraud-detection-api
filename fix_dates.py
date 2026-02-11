with open('app.py', 'r') as f:
    content = f.read()

# Fix all date references
content = content.replace('March 15-21, 2026', 'January 15-21, 2026')
content = content.replace('2026-03-15', '2026-01-15')
content = content.replace('2026-03-21', '2026-01-21')
content = content.replace('datetime(2026, 3, 15', 'datetime(2026, 1, 15')
content = content.replace('f"2026-03-{15 + day}"', 'f"2026-01-{15 + day}"')
content = content.replace('"2026-03-15 to 2026-03-21"', '"2026-01-15 to 2026-01-21"')

with open('app.py', 'w') as f:
    f.write(content)

print("✅ All dates fixed to January 2026")
