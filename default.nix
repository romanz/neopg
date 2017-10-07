let
   pkgs = import <nixpkgs> {};
in pkgs.stdenv.mkDerivation rec {
  name = "glutin-env";
  buildInputs = with pkgs; [ pkgconfig cmake gtest clang gcc boost sqlite botan2 openldap zlib bzip2 gnutls libusb ];
}
