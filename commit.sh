#!/bin/bash

# Pastikan file ini dijalankan dari root direktori Git
if [ ! -d ".git" ]; then
  echo "Error: Ini bukan direktori Git."
  exit 1
fi

FILE_TO_IGNORE="config.json"

# --- 1. Tandai config.json sebagai 'assume-unchanged' ---
# Ini memberitahu Git untuk mengabaikan perubahan lokal pada file ini.
echo "Menandai '$FILE_TO_IGNORE' sebagai 'assume-unchanged' secara lokal..."
git update-index --assume-unchanged "$FILE_TO_IGNORE"

# --- 2. Staging semua file yang dilacak ---
echo "Staging semua file yang berubah..."
git add .

# --- 3. Minta pesan commit dan buat commit ---
echo ""
read -p "Masukkan Pesan Commit (Contoh: fix(core): Perbaikan logika timeout): " COMMIT_MESSAGE

if [ -z "$COMMIT_MESSAGE" ]; then
  echo "Commit dibatalkan: Pesan commit tidak boleh kosong."
  # Penting: batalkan staging jika commit batal
  git reset
  exit 1
fi

echo ""
echo "Membuat commit dengan pesan: '$COMMIT_MESSAGE'"
git commit -m "$COMMIT_MESSAGE"

echo ""
echo "✅ Selesai! $FILE_TO_IGNORE sekarang diabaikan secara lokal dan commit telah dibuat."
