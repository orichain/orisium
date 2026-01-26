#!/usr/bin/env bash

echo "==> Removing old Neovim config..."
rm -rf ~/.config/nvim \
  ~/.local/share/nvim \
  ~/.local/state/nvim \
  ~/.cache/nvim

OS_TYPE=$(uname -s)
case "$OS_TYPE" in
    OpenBSD|FreeBSD|NetBSD)
        DISTRO_ID=$(echo "$OS_TYPE" | tr '[:upper:]' '[:lower:]')
        PKG_MGR="doas pkg_add"
        ;;
    Linux)
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            DISTRO_ID=$ID
        else
            DISTRO_ID="unknown_linux"
        fi
        if [ "$DISTRO_ID" = "rocky" ] || [ "$DISTRO_ID" = "fedora" ] || [ "$DISTRO_ID" = "rhel" ]; then
            PKG_MGR="doas dnf"
        elif [ "$DISTRO_ID" = "ubuntu" ] || [ "$DISTRO_ID" = "debian" ]; then
            PKG_MGR="sudo apt-get"
        fi
        ;;
    *)
        DISTRO_ID="unknown"
        ;;
esac
echo "==> Target System: $DISTRO_ID"
if [ "$DISTRO_ID" = "openbsd" ]; then
    echo "==> Configuring for OpenBSD..."
    doas pkg_add neovim unzip luarocks-lua54 git bear spdlog clang-tools-extra-21.1.2 llvm-21.1.2p0 xclip
    doas rm -f /usr/local/bin/luarocks /usr/local/bin/luarocks-admin /usr/local/bin/lua
    doas ln -sf /usr/local/bin/luarocks-5.4 /usr/local/bin/luarocks
    doas ln -sf /usr/local/bin/luarocks-admin-5.4 /usr/local/bin/luarocks-admin
    doas ln -sf /usr/local/bin/lua54 /usr/local/bin/lua
elif [ "$DISTRO_ID" = "rocky" ]; then
    echo "==> Configuring for Rocky..."
    sudo dnf -y install unzip luarocks git spdlog clang-tools-extra clang llvm xclip
    curl -LO https://github.com/neovim/neovim/releases/download/v0.11.5/nvim-linux-x86_64.tar.gz
    tar -xzf nvim-linux-x86_64.tar.gz
    rm nvim-linux-x86_64.tar.gz
    sudo rm -rf /usr/local/lib/nvim-dist
    sudo mv nvim-linux-x86_64 /usr/local/lib/nvim-dist
    sudo chmod +x /usr/local/lib/nvim-dist
    sudo ln -sf /usr/local/lib/nvim-dist/bin/nvim /usr/local/bin/nvim
    sudo dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm
    sudo dnf install -y https://dl.rockylinux.org/pub/rocky/9/devel/x86_64/os/Packages/p/protobuf-3.14.0-16.el9.x86_64.rpm
    sudo dnf install -y https://dl.rockylinux.org/pub/rocky/9/devel/x86_64/os/Packages/p/protobuf-compiler-3.14.0-16.el9.x86_64.rpm
    curl -L https://github.com/fcying/compiledb-go/releases/download/v1.5.2/compiledb-linux-amd64.txz -o compiledb.txz
    sudo dnf -y install bear
else
    echo "Not Automaticly Support For Distro [$DISTRO_ID]."
    exit 1
fi

echo "==> Installing Nerd Font (0xProto)..."
mkdir -p ~/.local/share/fonts
curl -LO https://github.com/ryanoasis/nerd-fonts/releases/download/v3.1.1/0xProto.zip
unzip -q 0xProto.zip -d ~/.local/share/fonts/0xProto
rm 0xProto.zip
fc-cache -fv

echo "==> Installing Neovim config..."
git clone --depth 1 https://github.com/orichain/orinvim.git ~/.config/nvim
mkdir -p ~/.local/share/nvim/lazy
git clone https://github.com/nvim-treesitter/nvim-treesitter.git ~/.local/share/nvim/lazy/nvim-treesitter
echo "==> Syncing plugins (please wait)..."
nvim --headless "+Lazy! sync" +qa
echo "==> Done. Launching nvim..."
exec nvim

