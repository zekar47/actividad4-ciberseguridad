{
  description = "Actividad 4: laboratorio DVWA/ZAP (parte 1) y API segura en C (parte 2)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
    in {
      devShells.${system} = {
        default = pkgs.mkShell {
          name = "a4-ciberseguridad";

          packages = with pkgs; [
            # Parte 1: DVWA + OWASP ZAP
            php
            mariadb
            zap
            curl
            jq
            python3
            # Parte 2: API en C sin dependencias externas
            gcc
            gnumake
            # Utilidades del laboratorio
            git
            nmap
            openssl
          ];

          shellHook = ''
            export A4_ROOT="$PWD"
            export A4_LAB="$PWD/.lab"
            export PATH="$A4_LAB/bin:$PATH"
            echo "a4: entorno cargado (php $(php -r 'echo PHP_VERSION;'))"
          '';
        };

        # Entorno auxiliar para regenerar las capturas del informe.
        screenshots = pkgs.mkShell {
          name = "a4-capturas";

          packages = with pkgs; [
            chromium
            chromedriver
            (python3.withPackages (ps: [ ps.selenium ps.pillow ]))
            curl
            jq
          ];
        };
      };
    };
}
