#!/bin/bash

if [ ! -d ".git" ]; then
  echo "Error: Ini bukan direktori Git."
  exit 1
fi

FILE_TO_IGNORE="config.json"

echo "Menandai '$FILE_TO_IGNORE' sebagai 'assume-unchanged' secara lokal..."
git update-index --assume-unchanged "$FILE_TO_IGNORE"

echo "Staging semua file yang berubah..."
git add .

echo ""
read -p "Masukkan Pesan Commit (Contoh: fix(core): Perbaikan logika timeout): " COMMIT_MESSAGE

if [ -z "$COMMIT_MESSAGE" ]; then
  echo "Commit dibatalkan: Pesan commit tidak boleh kosong."
  git reset
  exit 1
fi

echo ""
echo "Membuat commit dengan pesan: '$COMMIT_MESSAGE'"
git commit -m "$COMMIT_MESSAGE"

echo ""
echo "Selesai! $FILE_TO_IGNORE sekarang diabaikan secara lokal dan commit telah dibuat."
