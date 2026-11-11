{ projectRoot }:
let
  project = builtins.getFlake ("git+file://" + builtins.replaceStrings [ " " ] [ "%20" ] projectRoot);
  pkgs = import project.inputs.nixpkgs { system = builtins.currentSystem; };
  closure = pkgs.closureInfo { rootPaths = [ pkgs.bashInteractive pkgs.util-linux ]; };
in pkgs.runCommand "nexus-command-runtime-fixture" {} ''
  mkdir -p "$out/bin" "$out/usr/bin" "$out/nix/store" "$out/tmp" "$out/workspace"
  while IFS= read -r package; do
    cp -a "$package" "$out/nix/store/$(basename "$package")"
  done < ${closure}/store-paths
  cp -L ${pkgs.bashInteractive}/bin/bash "$out/bin/bash"
  cp -L ${pkgs.util-linux}/bin/prlimit "$out/usr/bin/prlimit"
''
