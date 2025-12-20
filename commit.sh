#!/usr/bin/env bash

if [ ! -d ".git" ]; then
    echo "Error: Ini bukan direktori Git."
    exit 1
fi

FILE_TO_IGNORE="config.json"

if [ -f "$FILE_TO_IGNORE" ]; then
    git update-index --assume-unchanged "$FILE_TO_IGNORE"
    echo "Info: '$FILE_TO_IGNORE' ditandai sebagai assume-unchanged."
fi

git add .

echo ""
printf "Masukkan Pesan Commit: "
read COMMIT_MESSAGE

if [ -z "$COMMIT_MESSAGE" ]; then
    echo "Error: Pesan commit kosong, membatalkan..."
    git reset
    exit 1
fi

if git commit -m "$COMMIT_MESSAGE"; then
    echo ""
    echo "Sukses: Commit berhasil dibuat di $(uname -s)."
else
    echo "Error: Gagal membuat commit."
    exit 1
fi
