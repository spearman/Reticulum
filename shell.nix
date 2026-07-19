with import <nixpkgs> {};
let
  # pipx seems broken on 26.05 stable, use unstable instead
  unstable = import
    (fetchTarball "https://github.com/NixOS/nixpkgs/archive/nixos-unstable.tar.gz") {};
in
mkShell {
  buildInputs = [
    #pipenv   # pipenv v2026.5.1 terminal input is broken, install using pipx
    unstable.pipx      # only added to install fix for pipenv
    poetry
    (python3.withPackages (p: with p; [
      docutils
      ipython
      memory-profiler
      numpy
      python-lsp-server
    ]))
  ];
  shellHook = ''
    pipx install pipenv
    pipenv install
    source "$(pipenv --venv)/bin/activate"
  '';
  PIPENV_VENV_IN_PROJECT = "1";
}
