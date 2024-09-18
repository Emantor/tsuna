{ lib
, rustPlatform
, fetchFromGitHub
, pkg-config
, openssl
, stdenv
, darwin
}:

rustPlatform.buildRustPackage rec {
  pname = "tsuna";
  version = "unstable-2023-04-02";

  src = fetchFromGitHub {
    owner = "Emantor";
    repo = "tsuna";
    rev = "b12222e0448c2ccb8ef7be0cee7e2aff0a4e2549";
    hash = "sha256-94TcRYXVDQzQKt7hEkLh4EGSL0edZj3F2QLJRXqFpcc=";
  };

  cargoHash = "sha256-ql4kojRXXHBSQVPDev8xtM+fhGE6CtnPWXxYHBCHLmM=";

  nativeBuildInputs = [
    pkg-config
  ];

  buildInputs = [
    openssl
  ] ++ lib.optionals stdenv.isDarwin [
    darwin.apple_sdk.frameworks.CoreFoundation
    darwin.apple_sdk.frameworks.Security
  ];

  meta = with lib; {
    description = "Rust client for the pushover open client API";
    homepage = "https://github.com/Emantor/tsuna";
    license = licenses.gpl2Only;
    maintainers = with maintainers; [ emantor ];
  };
}
