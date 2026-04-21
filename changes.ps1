
# Copy them preserving folder structure
git diff --name-only HEAD -- "*.c" "*.h" "*.build" "*.yaml" "*.txt" "*.in"  | ForEach-Object {
    $dest = "C:\Users\ahmad\open5gsChanges\$_"
    New-Item -ItemType Directory -Force -Path (Split-Path $dest)
    Copy-Item $_ $dest
}


# Copy them preserving folder structure
git ls-files --others --exclude-standard -- "*.c" "*.h" "*.build" "*.yaml" "*.txt" "*.in" | ForEach-Object {
    $dest = "C:\Users\ahmad\open5gsChanges\$_"
    New-Item -ItemType Directory -Force -Path (Split-Path $dest)
    Copy-Item $_ $dest
}
