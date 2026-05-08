# List changed .c files
git diff --name-only HEAD -- "*.c" "*.h" "*.build" "*.txt"


# Copy them preserving folder structure
git diff --name-only HEAD -- "*.c" "*.h" "*.build"  "*.txt" | ForEach-Object {
    $dest = "C:\Users\ahmad\open5gsChangesV1\$_"
    New-Item -ItemType Directory -Force -Path (Split-Path $dest)
    Copy-Item $_ $dest
}

git ls-files --others --exclude-standard -- "*.c" "*.h" "*.build"  "*.txt"

# Copy them preserving folder structure
git ls-files --others --exclude-standard -- "*.c" "*.h" "*.build"  "*.txt" | ForEach-Object {
    $dest = "C:\Users\ahmad\open5gsChangesV1\$_"
    New-Item -ItemType Directory -Force -Path (Split-Path $dest)
    Copy-Item $_ $dest
}
