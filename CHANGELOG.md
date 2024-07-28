# Changelog

## [Unreleased]

### Added

- Add support for x86_32 binaries

## [0.1.2] - 2024-07-16

### Fixed

- Fix in-place reassembly failing to find the right destination interval in many cases
- Fix broken code generation in certain cases when using in-place reassembly
- Fix broken code generation for certain instructions because of bogus additional info

## [0.1.1] - 2024-07-10

### Fixed

- Fix assert triggering when processing trampolines from Themida 3.1.7+
- Fix PyInstaller Github action builds

## [0.1.0] - 2024-07-06

Initial release with support for Themida/Winlicense 3.x.  
This release has been tested on Themida up to v3.1.9.0.
