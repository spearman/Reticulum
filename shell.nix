with import <nixpkgs> {};
mkShell {
  buildInputs = [
    glab
    mypy
    (python3.withPackages (p: with p; [
      ipython
      python-lsp-server
      pytest
    ]))
    ruff
    uv
  ];
  PYTHONPATH="./RNS";
  shellHook = ''
    uv venv --allow-existing && source .venv/bin/activate
  '';
}
