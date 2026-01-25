#!/usr/bin/env bash

echo "==> Removing old Neovim config..."
rm -rf ~/.config/nvim \
  ~/.local/share/nvim \
  ~/.local/state/nvim \
  ~/.cache/nvim

echo "==> Installing packages..."
doas pkg_add neovim unzip luarocks-lua51 git bear spdlog clang-tools-extra xclip

echo "==> Installing Nerd Font (0xProto)..."
mkdir -p ~/.local/share/fonts
curl -LO https://github.com/ryanoasis/nerd-fonts/releases/download/v3.1.1/0xProto.zip
unzip -q 0xProto.zip -d ~/.local/share/fonts/0xProto
rm 0xProto.zip
fc-cache -fv

echo "==> Fixing Lua/Luarocks symlinks..."
doas rm -f /usr/local/bin/luarocks /usr/local/bin/luarocks-admin /usr/local/bin/lua
doas ln -sf /usr/local/bin/luarocks-5.1 /usr/local/bin/luarocks
doas ln -sf /usr/local/bin/luarocks-admin-5.1 /usr/local/bin/luarocks-admin
doas ln -sf /usr/local/bin/lua51 /usr/local/bin/lua

echo "==> Installing Neovim config..."
git clone --depth 1 https://github.com/orichain/orinvim.git ~/.config/nvim
mkdir -p ~/.local/share/nvim/lazy
git clone https://github.com/nvim-treesitter/nvim-treesitter.git ~/.local/share/nvim/lazy/nvim-treesitter

echo "==> Done. Launching nvim..."
exec nvim src/orisium.c
