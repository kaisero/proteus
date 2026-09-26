# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **A Go model of the PAN-OS configuration, generated from the schema PAN-OS
  itself ships.** Point the generator at a firewall or Panorama schema and it
  produces typed Go structs for every configuration object, 506 of them for
  Panorama and 454 for a firewall, so a tool can read a configuration file
  without hand-writing any of that structure.
- **Repository skeleton.** Project layout, build and lint configuration, CI, and
  the mandatory rules that govern the library.
