{
  description = "Nexus iOS development tools for NixOS";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
    in {
      packages.${system}.swift-fhs = pkgs.buildFHSEnv {
        name = "nexus-swift-fhs";
        targetPkgs = pkgs: with pkgs; [
          bashInteractive coreutils findutils gnugrep gnused git gnumake zip unzip
          ripgrep
          glibc glibc.dev gcc gcc-unwrapped binutils zlib openssl ncurses sqlite
          libxml2_13 libedit z3 curl python3 appimage-run util-linux gmp krb5 e2fsprogs patchelf
        ];
        profile = ''
          export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [ pkgs.ncurses pkgs.sqlite pkgs.libxml2_13 pkgs.libedit pkgs.z3 pkgs.zlib pkgs.openssl pkgs.curl pkgs.stdenv.cc.cc.lib pkgs.util-linux.lib pkgs.gmp pkgs.krb5 pkgs.e2fsprogs ]}:''${LD_LIBRARY_PATH:-}"
        '';
        runScript = "bash";
      };
      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          actionlint bash curl coreutils file git gh jq unzip zip python3 nodejs_24 go swift swiftpm sourcekit-lsp gnupg
          appimage-run gnumake pkg-config openssl zlib libxml2 libxml2_13 ncurses sqlite libedit libuuid z3
          clang stdenv.cc
        ];
        shellHook = ''
          export NEXUS_ROOT="$PWD"
          export PATH="$HOME/.local/share/swiftly/bin:$HOME/.local/bin:$PATH"
          export LD_LIBRARY_PATH="${pkgs.ncurses}/lib:${pkgs.sqlite.out}/lib:${pkgs.libxml2_13.out}/lib:${pkgs.util-linux.lib}/lib:${pkgs.openssl.out}/lib:${pkgs.libedit}/lib:${pkgs.z3}/lib:${pkgs.zlib}/lib:${pkgs.curl.out}/lib:${pkgs.stdenv.cc.cc.lib}/lib:''${LD_LIBRARY_PATH:-}"
          export CPATH="${pkgs.stdenv.cc.libc.dev}/include:''${CPATH:-}"
          if [[ ! -d "$PWD/outputs/out/lib" && -n "''${NIX_LDFLAGS:-}" ]]; then
            export NIX_LDFLAGS="$(python3 -c 'import os; f=os.environ.get("NIX_LDFLAGS", ""); p=os.environ["PWD"] + "/outputs/out/lib"; print(f.replace("-rpath " + p + " ", ""))')"
          fi
          echo "Nexus Linux tools ready. Run ./scripts/dev-doctor.sh for toolchain and SDK status."
        '';
      };
    };
}
